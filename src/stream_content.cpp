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
 * @file stream_content.cpp
 * @brief Follow stream content: reading a stream back, rendering, export.
 */

#include "stream_content.h"

#include <QFile>

#include <algorithm>
#include <utility>

namespace tcpdump {

namespace {

constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpAck = 0x10;

constexpr size_t kBytesPerLine = 16;
/// Lines of the server's direction in a hex dump are indented, as Wireshark's are.
const QString kServerIndent = QStringLiteral( "    " );

/// The length of the UTF-8 sequence at @p data, at most @p len bytes long,
/// and its code point; 0 if it is none.
size_t utf8Sequence( const uint8_t* data, size_t len, char32_t& codePoint )
{
    const uint8_t lead = data[ 0 ];
    size_t length = 0;
    uint8_t low = 0x80, high = 0xBF; // the range of the second byte
    if ( lead >= 0xC2 && lead <= 0xDF ) {
        length = 2;
        codePoint = lead & 0x1F;
    }
    else if ( lead >= 0xE0 && lead <= 0xEF ) {
        length = 3;
        codePoint = lead & 0x0F;
        low = lead == 0xE0 ? 0xA0 : 0x80;  // no overlong form
        high = lead == 0xED ? 0x9F : 0xBF; // no surrogate
    }
    else if ( lead >= 0xF0 && lead <= 0xF4 ) {
        length = 4;
        codePoint = lead & 0x07;
        low = lead == 0xF0 ? 0x90 : 0x80;
        high = lead == 0xF4 ? 0x8F : 0xBF; // not past U+10FFFF
    }
    if ( length == 0 || length > len ) {
        return 0;
    }
    for ( size_t i = 1; i < length; ++i ) {
        const uint8_t byte = data[ i ];
        if ( byte < ( i == 1 ? low : 0x80 ) || byte > ( i == 1 ? high : 0xBF ) ) {
            return 0;
        }
        codePoint = ( codePoint << 6 ) | ( byte & 0x3F );
    }
    return length;
}

void appendEscaped( QString& out, uint8_t byte )
{
    static const char* const kDigits = "0123456789abcdef";
    out += QLatin1String( "\\x" );
    out += QLatin1Char( kDigits[ byte >> 4 ] );
    out += QLatin1Char( kDigits[ byte & 0x0F ] );
}

/// Wireshark's hex dump of @p len bytes at @p data, whose first is byte
/// @p offset of its direction: a line of 16, each after @p indent.
QString hexLines( const uint8_t* data, size_t len, uint64_t offset, const QString& indent )
{
    static const char* const kDigits = "0123456789abcdef";
    QString out;
    out.reserve( static_cast<qsizetype>( ( len / kBytesPerLine + 1 ) * ( 80 + indent.size() ) ) );
    for ( size_t line = 0; line < len; line += kBytesPerLine ) {
        const auto count = std::min( kBytesPerLine, len - line );
        out += indent;
        out += QStringLiteral( "%1  " ).arg( static_cast<qulonglong>( offset + line ), 8, 16,
                                             QLatin1Char( '0' ) );
        for ( size_t i = 0; i < kBytesPerLine; ++i ) {
            if ( i < count ) {
                const auto byte = data[ line + i ];
                out += QLatin1Char( kDigits[ byte >> 4 ] );
                out += QLatin1Char( kDigits[ byte & 0x0F ] );
                out += QLatin1Char( ' ' );
            }
            else {
                out += QLatin1String( "   " );
            }
            if ( i == 7 ) {
                out += QLatin1Char( ' ' );
            }
        }
        out += QLatin1String( "  " );
        for ( size_t i = 0; i < count; ++i ) {
            const auto byte = data[ line + i ];
            out += byte >= 0x20 && byte < 0x7F ? QLatin1Char( static_cast<char>( byte ) )
                                               : QLatin1Char( '.' );
        }
        out += QLatin1Char( '\n' );
    }
    return out;
}

QString missingText( uint64_t missing )
{
    return QStringLiteral( "[%1 bytes missing]" ).arg( static_cast<qulonglong>( missing ) );
}

} // namespace

// ── StreamEnds ───────────────────────────────────────────────────────────

QString StreamEnds::name( unsigned end ) const
{
    const auto address = QString::fromStdString( ip[ end ] );
    return ( address.contains( ':' ) ? QStringLiteral( "[%1]:%2" ) : QStringLiteral( "%1:%2" ) )
        .arg( address )
        .arg( port[ end ] );
}

// ── StreamContentReader ──────────────────────────────────────────────────

StreamContentReader::StreamContentReader( std::shared_ptr<const CaptureIndex> index,
                                          uint32_t number, int streamId )
    : index_( std::move( index ) )
    , number_( number )
    , streamId_( streamId )
{
}

StreamContentReader::~StreamContentReader() = default;

bool StreamContentReader::open()
{
    error_.clear();
    if ( !index_ ) {
        error_ = QStringLiteral( "No capture." );
        return false;
    }
    cursor_ = std::make_unique<CaptureCursor>( index_ );
    CapturedPacket packet;
    if ( !cursor_->read( number_, packet ) ) {
        error_ = QStringLiteral( "Packet %1: %2" ).arg( number_ ).arg( cursor_->error() );
        return false;
    }
    const auto& record = packet.record;
    if ( !record.transport ) {
        error_ = QStringLiteral( "Packet %1 belongs to no TCP or UDP stream." ).arg( number_ );
        return false;
    }
    ends_.transport = *record.transport;
    ends_.ip[ 0 ] = record.srcIp;
    ends_.ip[ 1 ] = record.dstIp;
    ends_.port[ 0 ] = record.srcPort;
    ends_.port[ 1 ] = record.dstPort;

    // The stream's packets lie between its first and last; one the plugin
    // did not number may lie anywhere.
    first_ = 1;
    last_ = index_->packets();
    if ( const auto extent = index_->streamExtent( ends_.transport, streamId_ );
         extent && extent->first <= number_ && number_ <= extent->last ) {
        first_ = extent->first;
        last_ = extent->last;
    }
    // A ring buffer's packets of files deleted since are not there to read.
    first_ = std::max( first_, index_->rotatedAway() + 1 );
    next_ = first_;
    opened_ = true;
    return true;
}

int StreamContentReader::directionOf( const PacketRecord& pkt ) const
{
    if ( pkt.transport != ends_.transport ) {
        return -1;
    }
    for ( unsigned direction : { 0u, 1u } ) {
        if ( pkt.srcIp == ends_.ip[ direction ] && pkt.srcPort == ends_.port[ direction ]
             && pkt.dstIp == ends_.ip[ 1 - direction ]
             && pkt.dstPort == ends_.port[ 1 - direction ] ) {
            return static_cast<int>( direction );
        }
    }
    return -1;
}

StreamContentReader::Status
StreamContentReader::read( const std::function<void( StreamChunk&& )>& sink, uint64_t budget,
                           const std::atomic_bool* cancel,
                           const std::function<void( uint32_t, uint32_t )>& progress )
{
    if ( !opened_ && !open() ) {
        return Status::Failed;
    }
    sink_ = &sink;
    handedOut_ = 0;
    const uint32_t total = last_ - first_ + 1;
    uint32_t lastPermille = 1001;
    CapturedPacket packet;
    while ( next_ <= last_ ) {
        if ( cancel && cancel->load() ) {
            return Status::Cancelled;
        }
        if ( !cursor_->read( next_, packet ) ) {
            error_ = QStringLiteral( "Packet %1: %2" ).arg( next_ ).arg( cursor_->error() );
            return Status::Failed;
        }
        const auto number = next_++;
        if ( progress ) {
            const uint32_t done = number - first_ + 1;
            const auto permille = static_cast<uint32_t>( uint64_t{ done } * 1000 / total );
            if ( permille != lastPermille ) {
                lastPermille = permille;
                progress( done, total );
            }
        }
        int direction = directionOf( packet.record );
        if ( direction < 0 ) {
            continue;
        }
        if ( !endsKnown_ ) {
            // The client sent the first packet, unless it is the SYN-ACK
            // of a handshake whose SYN was not captured.
            endsKnown_ = true;
            const auto flags = packet.record.tcpFlags;
            const bool synAck = ends_.transport == Transport::Tcp
                                && ( flags & ( kTcpSyn | kTcpAck ) ) == ( kTcpSyn | kTcpAck );
            if ( ( direction == 1 ) != synAck ) {
                std::swap( ends_.ip[ 0 ], ends_.ip[ 1 ] );
                std::swap( ends_.port[ 0 ], ends_.port[ 1 ] );
                direction = 1 - direction;
            }
        }
        take( static_cast<unsigned>( direction ), number, packet.record, packet.bytes );
        if ( handedOut_ >= budget && next_ <= last_ ) {
            return Status::More;
        }
    }
    if ( !flushed_ ) {
        // What still waits for bytes before it gets them no more.
        flushed_ = true;
        flush( 0, last_ );
        flush( 1, last_ );
    }
    return Status::Done;
}

void StreamContentReader::take( unsigned direction, uint32_t packet, const PacketRecord& record,
                                const std::vector<uint8_t>& bytes )
{
    const size_t offset = record.payloadOffset;
    const size_t captured = offset < bytes.size()
                                ? std::min<size_t>( record.payloadCaptured, bytes.size() - offset )
                                : 0;
    const ByteView payload{ captured ? bytes.data() + offset : nullptr, captured };
    if ( ends_.transport == Transport::Tcp ) {
        takeTcp( direction, packet, record, payload );
        return;
    }
    // A datagram: taken as it comes, the part cut at the snaplen missing.
    if ( payload.size > 0 ) {
        handOut( direction, packet, payload.data, payload.size );
    }
    if ( record.payloadLen > payload.size ) {
        handOutGap( direction, packet, record.payloadLen - payload.size );
    }
}

void StreamContentReader::takeTcp( unsigned direction, uint32_t packet, const PacketRecord& record,
                                   ByteView payload )
{
    if ( record.tcpHeaderLen < 20 ) {
        return; // a bogus header: where its payload lies is unknown
    }
    const auto flags = record.tcpFlags;
    const uint32_t seq = record.tcpSeq + ( ( flags & kTcpSyn ) ? 1 : 0 );
    auto& order = order_[ direction ];
    if ( flags & kTcpSyn ) {
        // A handshake, perhaps of a new connection on the same ports: its
        // bytes begin after the SYN.
        flush( direction, packet );
        order.reset( seq );
        started_[ direction ] = true;
        finSeq_[ direction ].reset();
    }
    const unsigned other = 1 - direction;
    if ( ( flags & kTcpAck ) && started_[ other ] ) {
        // The other side's bytes up to the acknowledged ones were sent: those
        // the capture lacks are missing.
        skipTo( other, record.tcpAck, packet );
    }
    if ( record.payloadLen > 0 ) {
        if ( !started_[ direction ] ) {
            order.reset( seq ); // the capture began after the handshake
            started_[ direction ] = true;
        }
        // A segment cut at the snaplen gives what was captured; the rest is
        // a gap the bytes after it show.
        for ( bool placed = payload.size == 0; !placed; ) {
            placed = true;
            const auto place = order.place( seq, payload.size );
            if ( place.fit == ByteStreamOrderer::Fit::Next ) {
                order.advance( payload.size - place.overlap );
                handOut( direction, packet, payload.data + place.overlap,
                         payload.size - place.overlap );
                popNext( direction, packet );
            }
            else if ( place.fit == ByteStreamOrderer::Fit::Early
                      && !order.holds( seq, payload.size ) ) {
                if ( order.early().size() >= kMaxEarlySegments
                     || order.earlyBytes() + payload.size > kMaxEarlyBytes ) {
                    flush( direction, packet ); // too much came early: a gap
                    placed = false;
                }
                else {
                    order.holdEarly( seq, payload );
                }
            }
            // Taken: a retransmission, its bytes shown once.
        }
    }
    if ( flags & kTcpFin ) {
        finSeq_[ direction ] = seq + record.payloadLen;
    }
}

void StreamContentReader::popNext( unsigned direction, uint32_t packet )
{
    std::vector<uint8_t> bytes;
    while ( order_[ direction ].popNext( bytes ) ) {
        order_[ direction ].advance( bytes.size() );
        sent_[ direction ] += bytes.size();
        handedOut_ += bytes.size();
        ( *sink_ )( StreamChunk{ direction, packet, 0, std::move( bytes ) } );
        bytes = {};
    }
}

void StreamContentReader::skipTo( unsigned direction, uint32_t seq, uint32_t packet )
{
    auto& order = order_[ direction ];
    if ( finSeq_[ direction ] && seqAfter( seq, *finSeq_[ direction ] ) > 0 ) {
        seq = *finSeq_[ direction ]; // the FIN takes a sequence number, no byte
    }
    if ( seqAfter( seq, order.nextSeq() ) <= 0 ) {
        return;
    }
    // The held segments before seq come after their own gaps.
    for ( auto first = order.firstEarlySeq(); first && seqAfter( *first, seq ) < 0;
          first = order.firstEarlySeq() ) {
        if ( const auto gap = order.skipTo( *first ) ) {
            handOutGap( direction, packet, gap );
        }
        popNext( direction, packet );
    }
    if ( const auto gap = order.skipTo( seq ) ) {
        handOutGap( direction, packet, gap );
    }
    popNext( direction, packet );
}

void StreamContentReader::flush( unsigned direction, uint32_t packet )
{
    auto& order = order_[ direction ];
    while ( const auto first = order.firstEarlySeq() ) {
        if ( const auto gap = order.skipTo( *first ) ) {
            handOutGap( direction, packet, gap );
        }
        popNext( direction, packet );
    }
}

void StreamContentReader::handOut( unsigned direction, uint32_t packet, const uint8_t* data,
                                   size_t len )
{
    if ( len == 0 ) {
        return;
    }
    sent_[ direction ] += len;
    handedOut_ += len;
    ( *sink_ )( StreamChunk{ direction, packet, 0, std::vector<uint8_t>( data, data + len ) } );
}

void StreamContentReader::handOutGap( unsigned direction, uint32_t packet, uint64_t missing )
{
    ( *sink_ )( StreamChunk{ direction, packet, missing, {} } );
}

// ── Rendering ────────────────────────────────────────────────────────────

QString streamText( const uint8_t* data, size_t len )
{
    QString out;
    out.reserve( static_cast<qsizetype>( len ) );
    for ( size_t i = 0; i < len; ++i ) {
        const uint8_t byte = data[ i ];
        if ( byte == '\r' && i + 1 < len && data[ i + 1 ] == '\n' ) {
            continue; // CR LF: a line break
        }
        if ( byte == '\n' || byte == '\t' || ( byte >= 0x20 && byte < 0x7F ) ) {
            out += QLatin1Char( static_cast<char>( byte ) );
            continue;
        }
        char32_t codePoint = 0;
        const auto length = utf8Sequence( data + i, len - i, codePoint );
        if ( length > 0 && codePoint >= 0xA0 ) { // not a C1 control
            out += QString::fromUcs4( &codePoint, 1 );
            i += length - 1;
            continue;
        }
        appendEscaped( out, byte );
    }
    return out;
}

StreamRenderer::StreamRenderer( StreamFormat format, unsigned directions, Transport transport )
    : format_( format )
    , directions_( directions )
    , transport_( transport )
{
}

QString StreamRenderer::render( const StreamChunk& chunk )
{
    const auto direction = chunk.direction;
    if ( !( directions_ & ( 1u << direction ) ) ) {
        return {};
    }
    QString out;
    const auto& indent = direction == 1 ? kServerIndent : QString();
    if ( format_ == StreamFormat::Hex ) {
        if ( chunk.missing > 0 ) {
            out = indent + missingText( chunk.missing ) + QLatin1Char( '\n' );
            offset_[ direction ] += chunk.missing;
        }
        else {
            out = hexLines( chunk.bytes.data(), chunk.bytes.size(), offset_[ direction ], indent );
            offset_[ direction ] += chunk.bytes.size();
        }
        return out;
    }

    // Text: a new direction, a datagram and a gap each begin a line.
    const bool ownLine = lastDirection_ != static_cast<int>( direction )
                         || transport_ == Transport::Udp || chunk.missing > 0 || lastWasGap_;
    if ( ownLine && !atLineStart_ ) {
        out += QLatin1Char( '\n' );
    }
    if ( chunk.missing > 0 ) {
        out += missingText( chunk.missing ) + QLatin1Char( '\n' );
        atLineStart_ = true;
    }
    else {
        const auto text = streamText( chunk.bytes.data(), chunk.bytes.size() );
        out += text;
        if ( !text.isEmpty() ) {
            atLineStart_ = text.endsWith( QLatin1Char( '\n' ) );
        }
    }
    lastDirection_ = static_cast<int>( direction );
    lastWasGap_ = chunk.missing > 0;
    return out;
}

// ── Export ───────────────────────────────────────────────────────────────

StreamExport exportStreamContent( StreamContentReader& reader, const QString& path, bool raw,
                                  StreamFormat format, unsigned directions,
                                  const std::atomic_bool* cancel,
                                  const std::function<void( uint32_t, uint32_t )>& progress )
{
    using Status = StreamContentReader::Status;
    StreamExport result;
    QFile file( path );
    if ( !file.open( QIODevice::WriteOnly | QIODevice::Truncate ) ) {
        result.status = Status::Failed;
        result.error = QStringLiteral( "Cannot write %1: %2" ).arg( path, file.errorString() );
        return result;
    }

    StreamRenderer renderer( format, directions, reader.ends().transport );
    bool writeFailed = false;
    const std::function<void( StreamChunk&& )> sink = [ & ]( StreamChunk&& chunk ) {
        if ( writeFailed ) {
            return;
        }
        QByteArray data;
        if ( raw ) {
            if ( chunk.missing > 0 || !( directions & ( 1u << chunk.direction ) ) ) {
                return;
            }
            data = QByteArray::fromRawData( reinterpret_cast<const char*>( chunk.bytes.data() ),
                                            static_cast<qsizetype>( chunk.bytes.size() ) );
        }
        else {
            data = renderer.render( chunk ).toUtf8();
        }
        if ( file.write( data ) != data.size() ) {
            writeFailed = true;
            return;
        }
        result.bytes += static_cast<uint64_t>( data.size() );
    };

    // A budget at a time, so that a packet's worth is held, not the stream.
    constexpr uint64_t kBudget = 1024 * 1024;
    do {
        result.status = reader.read( sink, kBudget, cancel, progress );
    } while ( result.status == Status::More && !writeFailed );
    if ( writeFailed || ( result.status == Status::Done && !file.flush() ) ) {
        result.status = Status::Failed;
        result.error = QStringLiteral( "Cannot write %1: %2" ).arg( path, file.errorString() );
    }
    else if ( result.status == Status::Failed ) {
        result.error = reader.error();
    }
    file.close();
    if ( result.status != Status::Done ) {
        file.remove();
    }
    return result;
}

} // namespace tcpdump
