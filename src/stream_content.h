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
 * @file stream_content.h
 * @brief Follow stream content: the payload of a conversation, read back
 *        from its capture in order, shown as text or hex and exported.
 *
 * The packet list holds no payload, and the Converter keeps none: the
 * StreamContentReader reads the stream's packets again from the capture
 * file, through a CaptureCursor and the CaptureIndex, from the stream's
 * first packet to its last.  A TCP stream's bytes are put in sequence order
 * per direction by a ByteStreamOrderer, as the TCP Reassembly orders them;
 * a UDP stream's datagrams are taken as they come.  The reader hands the
 * content out in StreamChunks, a budget of bytes at a time, so that what is
 * shown is bounded and an export never holds the stream.
 */

#pragma once

#include "byte_stream_orderer.h"
#include "capture_index.h"
#include "pcap_parser.h"

#include <QString>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace tcpdump {

/// The two ends of a followed conversation; end 0 is the client, the side
/// that sent the stream's first packet (or the SYN a SYN-ACK answers).
struct StreamEnds {
    Transport transport = Transport::Tcp;
    std::string ip[ 2 ];
    uint16_t port[ 2 ] = { 0, 0 };

    /// "192.0.2.10:50004" for end @p end; an IPv6 address in brackets.
    QString name( unsigned end ) const;
};

/// A piece of a stream's content, in the order it is shown.
struct StreamChunk {
    /// 0: sent by the client (StreamEnds end 0), 1: by the server.
    unsigned direction = 0;
    /// The packet the bytes came in; for bytes that came early, the
    /// packet that let them follow.
    uint32_t packet = 0;
    /// Bytes the capture lacks here (a gap), and bytes is empty; 0 for
    /// bytes of the stream.
    uint64_t missing = 0;
    std::vector<uint8_t> bytes;
};

/**
 * Reads the content of the stream of one packet back from its capture.  One
 * reader serves one thread at a time; it keeps where it is between read()s.
 */
class StreamContentReader {
public:
    /// Bytes of a TCP direction held at most while they wait for those
    /// before them; beyond, the bytes before them are taken as missing.
    static constexpr size_t kMaxEarlyBytes = 1024 * 1024;
    /// Segments of a direction held at most the same way.
    static constexpr size_t kMaxEarlySegments = 64;

    enum class Status {
        More,      ///< The budget was reached: read() goes on.
        Done,      ///< The stream ended.
        Cancelled, ///< The cancel flag was set.
        Failed,    ///< See error().
    };

    /**
     * Follow the stream of packet @p number of the capture @p index points
     * into, the stream the Stream column numbers @p streamId (as that of
     * its transport); for an unnumbered one (a negative id), the whole
     * capture is looked through for its packets.
     */
    StreamContentReader( std::shared_ptr<const CaptureIndex> index, uint32_t number, int streamId );
    ~StreamContentReader();
    StreamContentReader( const StreamContentReader& ) = delete;
    StreamContentReader& operator=( const StreamContentReader& ) = delete;

    /// Read packet @p number and find its stream; false, with error(), for
    /// a packet of no TCP or UDP stream or one that cannot be read.
    bool open();

    /**
     * Read on, handing out the content to @p sink, until @p budget bytes of
     * it were handed out (then at the end of a packet), the stream ends or
     * @p cancel is set.  @p progress, if set, is told the packets read and
     * those to read.
     */
    Status read( const std::function<void( StreamChunk&& )>& sink, uint64_t budget,
                 const std::atomic_bool* cancel = nullptr,
                 const std::function<void( uint32_t, uint32_t )>& progress = {} );

    const StreamEnds& ends() const
    {
        return ends_;
    }

    /// The stream's number, as the Stream column shows it, or a negative id.
    int streamId() const
    {
        return streamId_;
    }

    /// Bytes of each direction handed out so far, gaps not counted.
    uint64_t bytesSent( unsigned direction ) const
    {
        return sent_[ direction ];
    }

    /// Why open() or read() failed, for the user.
    const QString& error() const
    {
        return error_;
    }

private:
    /// The direction of @p pkt in the stream, or -1 if it is not of it.
    int directionOf( const PacketRecord& pkt ) const;
    void take( unsigned direction, uint32_t packet, const PacketRecord& record,
               const std::vector<uint8_t>& bytes );
    void takeTcp( unsigned direction, uint32_t packet, const PacketRecord& record,
                  ByteView payload );
    /// Hand out the bytes of @p direction that came early and are next now.
    void popNext( unsigned direction, uint32_t packet );
    /// Take the bytes of @p direction up to @p seq as missing, and those
    /// held up to there.
    void skipTo( unsigned direction, uint32_t seq, uint32_t packet );
    /// Take the bytes before every held segment of @p direction as missing.
    void flush( unsigned direction, uint32_t packet );
    void handOut( unsigned direction, uint32_t packet, const uint8_t* data, size_t len );
    void handOutGap( unsigned direction, uint32_t packet, uint64_t missing );

    std::shared_ptr<const CaptureIndex> index_;
    std::unique_ptr<CaptureCursor> cursor_;
    uint32_t number_;
    int streamId_;
    StreamEnds ends_;
    uint32_t first_ = 0; ///< The first packet to read.
    uint32_t last_ = 0;  ///< The last packet to read.
    uint32_t next_ = 0;  ///< The next packet to read.
    ByteStreamOrderer order_[ 2 ];
    bool started_[ 2 ] = { false, false };
    /// The sequence number after a direction's FIN, which the other side
    /// acknowledges without a byte missing; unset before its FIN.
    std::optional<uint32_t> finSeq_[ 2 ];
    /// Which end is the client is told by the first packet of the stream read.
    bool endsKnown_ = false;
    uint64_t sent_[ 2 ] = { 0, 0 };
    uint64_t handedOut_ = 0; ///< Bytes handed out in this read().
    const std::function<void( StreamChunk&& )>* sink_ = nullptr;
    bool opened_ = false;
    bool flushed_ = false;
    QString error_;
};

/// How the content is shown: as text or a hex dump.
enum class StreamFormat { Text, Hex };

/// Which directions are shown or exported: bit 1 << direction.
enum StreamDirections : unsigned {
    kClientToServer = 1,
    kServerToClient = 2,
    kBothDirections = 3,
};

/// The bytes at @p data as text: UTF-8 kept, CR LF as a line break, other
/// control bytes and bytes that are no UTF-8 escaped as \xNN.
QString streamText( const uint8_t* data, size_t len );

/**
 * Turns StreamChunks into the text the content is shown as, one after the
 * other: as text, each direction's run starting on a line of its own (each
 * datagram of a UDP stream, too); as a hex dump, Wireshark's, the offset
 * counted per direction and the server's lines indented.  A gap shows as
 * "[n bytes missing]".  Chunks of a direction not shown give nothing.
 */
class StreamRenderer {
public:
    StreamRenderer( StreamFormat format, unsigned directions, Transport transport );

    /// The text of @p chunk, to append after what was rendered before.
    QString render( const StreamChunk& chunk );

private:
    StreamFormat format_;
    unsigned directions_;
    Transport transport_;
    int lastDirection_ = -1;
    bool lastWasGap_ = false;
    bool atLineStart_ = true;
    uint64_t offset_[ 2 ] = { 0, 0 };
};

/// The outcome of exportStreamContent().
struct StreamExport {
    StreamContentReader::Status status = StreamContentReader::Status::Done;
    QString error;      ///< Why it failed.
    uint64_t bytes = 0; ///< Bytes written.
};

/**
 * Write the whole content of the stream @p reader follows (opened, read
 * from its start) to @p path: with @p raw, the bytes of @p directions as
 * they were sent, one after the other (gaps left out); otherwise as
 * StreamRenderer shows them, in @p format, as UTF-8.  Holds a packet's
 * worth at a time, however long the stream.  A failed or cancelled export
 * removes the file.
 */
StreamExport exportStreamContent( StreamContentReader& reader, const QString& path, bool raw,
                                  StreamFormat format, unsigned directions,
                                  const std::atomic_bool* cancel = nullptr,
                                  const std::function<void( uint32_t, uint32_t )>& progress = {} );

} // namespace tcpdump
