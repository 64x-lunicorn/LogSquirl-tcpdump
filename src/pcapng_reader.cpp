/*
 * Copyright (C) 2026 LogSquirl Contributors
 *
 * This file is part of logsquirl-tcpdump.
 *
 * logsquirl-tcpdump is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * logsquirl-tcpdump is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with logsquirl-tcpdump.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file pcapng_reader.cpp
 * @brief Implementation of the pcapng reader.
 */

#include "pcapng_reader.h"

#include "wire_bytes.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace tcpdump {

namespace {

// ── Block types and their smallest lengths ───────────────────────────────

constexpr uint32_t kSectionHeaderBlock = PcapNgMagic;
constexpr uint32_t kInterfaceBlock = 1;
constexpr uint32_t kSimplePacketBlock = 3;
constexpr uint32_t kEnhancedPacketBlock = 6;

constexpr uint32_t kByteOrderMagic = 0x1A2B3C4D;
constexpr uint32_t kByteOrderMagicSwapped = 0x4D3C2B1A;

/// Block type and length before the body, the length again after it.
constexpr uint32_t kBlockFrame = 12;
constexpr uint32_t kMinSectionHeader = kBlockFrame + 16;
constexpr uint32_t kMinInterface = kBlockFrame + 8;
constexpr uint32_t kMinSimplePacket = kBlockFrame + 4;
constexpr uint32_t kMinEnhancedPacket = kBlockFrame + 20;

constexpr uint16_t kOptionEnd = 0;
constexpr uint16_t kOptionTsresol = 9; ///< if_tsresol

/// The smallest length a block of @p type can have.
uint32_t minimumLength( uint32_t type )
{
    switch ( type ) {
    case kSectionHeaderBlock:
        return kMinSectionHeader;
    case kInterfaceBlock:
        return kMinInterface;
    case kSimplePacketBlock:
        return kMinSimplePacket;
    case kEnhancedPacketBlock:
        return kMinEnhancedPacket;
    default:
        return kBlockFrame;
    }
}

bool isPacketBlock( uint32_t type )
{
    return type == kEnhancedPacketBlock || type == kSimplePacketBlock;
}

uint64_t powerOfTen( uint8_t exponent )
{
    uint64_t result = 1;
    for ( uint8_t i = 0; i < exponent; ++i ) {
        result *= 10;
    }
    return result;
}

} // namespace

// ── Reading ──────────────────────────────────────────────────────────────

size_t PcapngReader::read( uint8_t* dst, size_t n )
{
    // An empty packet reads into a buffer whose data() may be null.
    if ( n == 0 ) {
        return 0;
    }
    size_t got = 0;
    while ( got < n ) {
        const auto more = source_.read( dst + got, n - got );
        if ( more == 0 ) {
            break;
        }
        got += more;
    }
    bytesRead_ += got;
    return got;
}

bool PcapngReader::skip( uint64_t n )
{
    const bool ok = n == 0 || source_.skip( n );
    bytesRead_ += n; // on failure the source is at its end anyway
    return ok;
}

bool PcapngReader::fail( const char* problem )
{
    problem_ = std::string( "Not a valid pcapng file (" ) + problem + ")";
    return false;
}

void PcapngReader::endBroken()
{
    truncated_ = true;
    open_ = false;
}

/// Read a block's type and length, and for a section header block the
/// byte-order magic, which says how to read the length.  False at the end
/// of the capture (problem_ empty) and for a block that cannot be read.
bool PcapngReader::readBlockHeader( BlockHeader& block )
{
    problem_.clear();
    uint8_t header[ 12 ];
    const auto got = read( header, 8 );
    if ( got == 0 ) {
        return false;
    }
    if ( got < 8 ) {
        return fail( "cut off inside a block header" );
    }
    block.type = read32( header, swap_ ); // a section header's reads the same either way
    block.consumed = 8;
    if ( block.type == kSectionHeaderBlock ) {
        if ( read( header + 8, 4 ) < 4 ) {
            return fail( "cut off inside a section header" );
        }
        block.consumed = 12;
        uint32_t magic;
        std::memcpy( &magic, header + 8, 4 );
        if ( magic != kByteOrderMagic && magic != kByteOrderMagicSwapped ) {
            return fail( "unknown byte-order magic" );
        }
        swap_ = magic == kByteOrderMagicSwapped;
    }
    block.length = read32( header + 4, swap_ );
    if ( block.length % 4 != 0 || block.length < minimumLength( block.type ) ) {
        return fail( "bad block length" );
    }
    return true;
}

/// Skip the rest of @p block's body and check the length after it.
bool PcapngReader::finishBlock( BlockHeader& block )
{
    uint8_t trailer[ 4 ];
    if ( !skip( block.length - 4 - block.consumed ) || read( trailer, 4 ) < 4 ) {
        return fail( "cut off inside a block" );
    }
    if ( read32( trailer, swap_ ) != block.length ) {
        return fail( "block lengths differ" );
    }
    return true;
}

/// Read a section header's version; a new section declares its own interfaces.
bool PcapngReader::readSectionHeader( BlockHeader& block )
{
    uint8_t fields[ 12 ]; // major, minor, section length
    if ( read( fields, sizeof( fields ) ) < sizeof( fields ) ) {
        return fail( "cut off inside a section header" );
    }
    block.consumed += sizeof( fields );
    const auto major = read16( fields, swap_ );
    if ( major != 1 ) {
        problem_ = "Unsupported pcapng format version " + std::to_string( major ) + "."
                   + std::to_string( read16( fields + 2, swap_ ) );
        return false;
    }
    interfaces_.clear();
    return finishBlock( block );
}

/// Read an interface's link-layer type, snaplen and if_tsresol option.
bool PcapngReader::readInterface( BlockHeader& block )
{
    if ( interfaces_.size() >= kMaxInterfaces ) {
        return fail( "too many interfaces" );
    }
    uint8_t fields[ 8 ]; // link type, reserved, snaplen
    if ( read( fields, sizeof( fields ) ) < sizeof( fields ) ) {
        return fail( "cut off inside an interface description" );
    }
    block.consumed += sizeof( fields );
    Interface iface;
    iface.linkType = read16( fields, swap_ );
    iface.snaplen = read32( fields + 4, swap_ );

    // Options: code and length, then the value padded to 32 bits.
    const uint32_t optionsEnd = block.length - 4;
    while ( block.consumed + 4 <= optionsEnd ) {
        uint8_t option[ 4 ];
        if ( read( option, 4 ) < 4 ) {
            return fail( "cut off inside an interface description" );
        }
        block.consumed += 4;
        const auto code = read16( option, swap_ );
        uint32_t length = ( read16( option + 2, swap_ ) + 3u ) & ~3u;
        if ( code == kOptionEnd ) {
            break;
        }
        if ( length > optionsEnd - block.consumed ) {
            return fail( "option beyond its block" );
        }
        if ( code == kOptionTsresol && length > 0 ) {
            uint8_t value;
            if ( read( &value, 1 ) < 1 ) {
                return fail( "cut off inside an interface description" );
            }
            iface.unit.binary = ( value & 0x80 ) != 0;
            iface.unit.exponent = value & 0x7F;
            block.consumed += 1;
            length -= 1;
        }
        if ( !skip( length ) ) {
            return fail( "cut off inside an interface description" );
        }
        block.consumed += length;
    }
    // A unit finer than 64 bits of timestamp can count is not one a capture has.
    if ( iface.unit.exponent > ( iface.unit.binary ? 63 : 19 ) ) {
        return fail( "timestamp unit too fine" );
    }
    const bool finerThanMicroseconds
        = iface.unit.binary ? iface.unit.exponent >= 20 : iface.unit.exponent > 6;
    iface.precision
        = finerThanMicroseconds ? TimePrecision::Nanoseconds : TimePrecision::Microseconds;
    if ( !finishBlock( block ) ) {
        return false;
    }

    interfaces_.push_back( iface );
    if ( !precisionAnnounced_ ) {
        precision_ = std::max( precision_, iface.precision );
    }
    if ( std::find( linkTypes_.begin(), linkTypes_.end(), iface.linkType ) == linkTypes_.end() ) {
        linkTypes_.push_back( iface.linkType );
    }
    return true;
}

/// Read an enhanced or simple packet block into @p pkt.
bool PcapngReader::readPacket( BlockHeader& block, PacketRecord& pkt )
{
    const Interface* iface = nullptr;
    uint64_t timestamp = 0;
    uint32_t capturedLen = 0;
    uint32_t originalLen = 0;
    const uint32_t room = block.length - minimumLength( block.type ); // for the packet's bytes
    if ( block.type == kEnhancedPacketBlock ) {
        uint8_t fields[ 20 ]; // interface, timestamp high and low, captured, original length
        if ( read( fields, sizeof( fields ) ) < sizeof( fields ) ) {
            return fail( "cut off inside a packet block" );
        }
        const auto interfaceId = read32( fields, swap_ );
        if ( interfaceId >= interfaces_.size() ) {
            return fail( "packet of an undeclared interface" );
        }
        iface = &interfaces_[ interfaceId ];
        timestamp = ( static_cast<uint64_t>( read32( fields + 4, swap_ ) ) << 32 )
                    | read32( fields + 8, swap_ );
        capturedLen = read32( fields + 12, swap_ );
        originalLen = read32( fields + 16, swap_ );
        if ( capturedLen > room ) {
            return fail( "packet longer than its block" );
        }
        block.consumed += sizeof( fields );
    }
    else {
        // A simple packet block belongs to the section's first interface,
        // has no timestamp, and is as long as the packet or the snaplen.
        uint8_t fields[ 4 ]; // original length
        if ( interfaces_.empty() ) {
            return fail( "packet of an undeclared interface" );
        }
        if ( read( fields, sizeof( fields ) ) < sizeof( fields ) ) {
            return fail( "cut off inside a packet block" );
        }
        iface = &interfaces_.front();
        originalLen = read32( fields, swap_ );
        capturedLen = std::min( originalLen, room );
        if ( iface->snaplen != 0 ) {
            capturedLen = std::min( capturedLen, iface->snaplen );
        }
        block.consumed += sizeof( fields );
    }

    // Only the first kMaxDissectedBytes are looked at; the rest is skipped.
    const auto kept = static_cast<size_t>( std::min( capturedLen, kMaxDissectedBytes ) );
    packet_.resize( kept );
    if ( read( packet_.data(), kept ) < kept || !skip( capturedLen - kept ) ) {
        return fail( "cut off inside a packet block" );
    }
    block.consumed += capturedLen;
    if ( !finishBlock( block ) ) {
        return false;
    }

    pkt = PacketRecord();
    pkt.number = ++packetCount_;
    const auto& unit = iface->unit;
    const uint64_t perSecond
        = unit.binary ? uint64_t{ 1 } << unit.exponent : powerOfTen( unit.exponent );
    const uint64_t fraction = timestamp % perSecond;
    uint64_t fractionNs = 0;
    if ( !unit.binary ) {
        fractionNs = unit.exponent <= 9 ? fraction * powerOfTen( 9 - unit.exponent )
                                        : fraction / powerOfTen( unit.exponent - 9 );
    }
    else if ( unit.exponent <= 34 ) {
        fractionNs = ( fraction * 1000000000 ) >> unit.exponent; // fits: fraction < 2^34
    }
    else {
        fractionNs = ( ( fraction >> ( unit.exponent - 34 ) ) * 1000000000 ) >> 34;
    }
    // Only a unit of whole seconds counts past what int64_t seconds hold,
    // some 292 billion years on: such a time is kept at the last one it holds.
    pkt.timestampSec = static_cast<int64_t>( std::min<uint64_t>(
        timestamp / perSecond, static_cast<uint64_t>( std::numeric_limits<int64_t>::max() ) ) );
    pkt.timestampNsec = static_cast<uint32_t>( fractionNs );
    pkt.capturedLen = capturedLen;
    pkt.originalLen = originalLen;
    pkt.linkType = iface->linkType;
    pkt.precision = std::min( iface->precision, precision_ );
    dissectPacket( pkt, pkt.linkType, swap_, packet_.data(), kept );
    return true;
}

/// Read blocks up to the next packet block, whose header is then pending.
/// False at the end of the capture and for a block that cannot be read.
bool PcapngReader::readBlocksUpToPacket()
{
    for ( ;; ) {
        BlockHeader block;
        if ( !readBlockHeader( block ) ) {
            return false;
        }
        bool ok = true;
        if ( isPacketBlock( block.type ) ) {
            pendingBlock_ = block;
            havePacketBlock_ = true;
            return true;
        }
        if ( block.type == kSectionHeaderBlock ) {
            ok = readSectionHeader( block );
        }
        else if ( block.type == kInterfaceBlock ) {
            ok = readInterface( block );
        }
        else {
            ok = finishBlock( block );
        }
        if ( !ok ) {
            return false;
        }
    }
}

// ── Opening and reading on ───────────────────────────────────────────────

bool PcapngReader::open()
{
    const auto& head = source_.peek( kMaxPreamble + 24 );
    CaptureFormat format = CaptureFormat::Pcap;
    const auto offset = findCaptureStart( head.data(), head.size(), format, error_ );
    if ( offset == head.size() ) {
        return false;
    }
    if ( format != CaptureFormat::Pcapng ) {
        error_ = "Not a pcapng file but a pcap one";
        return false;
    }
    skip( offset );

    // The first block is the first section's header; a capture that cannot
    // be read that far is no capture.
    BlockHeader block;
    if ( !readBlockHeader( block ) || !readSectionHeader( block ) ) {
        error_ = problem_;
        return false;
    }

    open_ = true;
    if ( !readBlocksUpToPacket() && !problem_.empty() ) {
        endBroken();
    }
    precisionAnnounced_ = true;
    return true;
}

bool PcapngReader::next( PacketRecord& pkt )
{
    if ( !open_ ) {
        return false;
    }
    if ( !havePacketBlock_ && !readBlocksUpToPacket() ) {
        if ( !problem_.empty() ) {
            endBroken();
        }
        open_ = false;
        return false;
    }
    havePacketBlock_ = false;
    if ( !readPacket( pendingBlock_, pkt ) ) {
        endBroken();
        return false;
    }
    return true;
}

} // namespace tcpdump
