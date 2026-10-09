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
 * @file doip_test.cpp
 * @brief BDD tests for the DoIP detector: every payload type of ISO
 *        13400-2, the header's pattern and lengths, several messages per
 *        datagram and segment, the UDS services, sub-functions and
 *        negative response codes of diagnostic messages, framing for the
 *        TCP Reassembly, and messages mangled and cut anywhere.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"
#include "pcapbuilder.h"

#include <random>
#include <string>
#include <utility>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint16_t kDoipPort = 13400;
constexpr uint16_t kTesterPort = 50000;
constexpr uint16_t kTester = 0x0E00;
constexpr uint16_t kEcu = 0x1000;

const std::string kEllipsis = "\xe2\x80\xa6";
const std::string kArrow = " \xe2\x86\x92 ";

/// A DoIP message: the generic header, then @p payload.
Bytes doip( uint16_t type, const Bytes& payload = {}, uint8_t version = 0x02 )
{
    Bytes b{ version, static_cast<uint8_t>( ~version ) };
    putBE16( b, type );
    putBE32( b, static_cast<uint32_t>( payload.size() ) );
    return b + payload;
}

/// Two logical addresses, then @p rest.
Bytes addressed( uint16_t source, uint16_t target, const Bytes& rest = {} )
{
    Bytes b;
    putBE16( b, source );
    putBE16( b, target );
    return b + rest;
}

/// A diagnostic message from the tester to the ECU carrying @p uds.
Bytes diagnostic( const Bytes& uds, uint16_t source = kTester, uint16_t target = kEcu )
{
    return doip( 0x8001, addressed( source, target, uds ) );
}

const Bytes kVin = text( "WP0ZZZ99ZTS392124" );
const Bytes kEid{ 0x02, 0x00, 0x5e, 0x00, 0x00, 0x10 };

Bytes announcement( std::optional<uint8_t> sync = std::nullopt, uint8_t furtherAction = 0x00 )
{
    Bytes b = kVin;
    putBE16( b, kEcu );
    b = b + kEid + kEid;
    b.push_back( furtherAction );
    if ( sync ) {
        b.push_back( *sync );
    }
    return doip( 0x0004, b );
}

PayloadDescription overUdp( const Bytes& payload, uint16_t port = kDoipPort )
{
    return describePayload( Transport::Udp, payload.data(), payload.size(), kTesterPort, port );
}

PayloadDescription overTcp( const Bytes& payload, uint16_t port = kDoipPort )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), kTesterPort, port );
}

/// The UDS part of the description of a diagnostic message carrying @p uds.
std::string uds( const Bytes& uds )
{
    const auto description = overTcp( diagnostic( uds ) ).description;
    const std::string head = "Diagnostic message 0x0E00" + kArrow + "0x1000, ";
    REQUIRE( description.rfind( head, 0 ) == 0 );
    return description.substr( head.size() );
}

Bytes prefix( const Bytes& bytes, size_t n )
{
    return Bytes( bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>( n ) );
}

} // namespace

SCENARIO( "Every payload type of ISO 13400-2 is named", "[doip]" )
{
    GIVEN( "the vehicle identification requests on UDP port 13400" )
    {
        THEN( "they are labelled DoIP and named as Wireshark names them" )
        {
            const auto plain = overUdp( doip( 0x0001, {}, 0xFF ) );
            REQUIRE( plain.label == "DoIP" );
            REQUIRE_FALSE( plain.guessed );
            REQUIRE( plain.description == "Vehicle identification request" );
            REQUIRE( overUdp( doip( 0x0002, kEid ) ).description
                     == "Vehicle identification request with EID, EID 02:00:5e:00:00:10" );
            REQUIRE( overUdp( doip( 0x0003, kVin ) ).description
                     == "Vehicle identification request with VIN, VIN WP0ZZZ99ZTS392124" );
        }
    }

    GIVEN( "a vehicle announcement" )
    {
        THEN( "its VIN, logical address, EID and GID are named" )
        {
            const std::string fields = "Vehicle announcement message/vehicle identification "
                                       "response message, VIN WP0ZZZ99ZTS392124, Logical address "
                                       "0x1000, EID 02:00:5e:00:00:10, GID 02:00:5e:00:00:10";
            REQUIRE( overUdp( announcement() ).description == fields );
            REQUIRE( overUdp( announcement( 0x00 ) ).description == fields );
            REQUIRE( overUdp( announcement( 0x10, 0x10 ) ).description
                     == fields
                            + ", Routing activation required to initiate central security, "
                              "VIN/GID not synchronized" );
        }
    }

    GIVEN( "routing activation over TCP" )
    {
        Bytes request;
        putBE16( request, kTester );
        request = request + Bytes{ 0x00, 0, 0, 0, 0 };
        Bytes response;
        putBE16( response, kTester );
        putBE16( response, kEcu );
        response = response + Bytes{ 0x10, 0, 0, 0, 0 };
        THEN( "the source address, activation type and response code are named" )
        {
            const auto result = overTcp( doip( 0x0005, request ) );
            REQUIRE( result.label == "DoIP" );
            REQUIRE( result.description
                     == "Routing activation request, Source 0x0E00, Activation type Default" );
            REQUIRE( overTcp( doip( 0x0005, request + Bytes( 4, 0 ) ) ).description
                     == result.description );
            REQUIRE( overTcp( doip( 0x0006, response ) ).description
                     == "Routing activation response, Tester 0x0E00, Entity 0x1000, Routing "
                        "successfully activated (0x10)" );
            auto denied = response;
            denied[ 4 ] = 0x00;
            REQUIRE( overTcp( doip( 0x0006, denied ) ).description
                     == "Routing activation response, Tester 0x0E00, Entity 0x1000, Routing "
                        "activation denied due to unknown source address (0x00)" );
            auto central = request;
            central[ 2 ] = 0xE0;
            REQUIRE( overTcp( doip( 0x0005, central ) ).description
                     == "Routing activation request, Source 0x0E00, Activation type Central "
                        "security" );
        }
    }

    GIVEN( "the other messages of the header's payload types" )
    {
        THEN( "each is named, with its fields" )
        {
            REQUIRE( overTcp( doip( 0x0007 ) ).description == "Alive check request" );
            REQUIRE( overTcp( doip( 0x0008, { 0x0E, 0x00 } ) ).description
                     == "Alive check response, Source 0x0E00" );
            REQUIRE( overUdp( doip( 0x4001 ) ).description == "DoIP entity status request" );
            REQUIRE( overUdp( doip( 0x4002, { 0x00, 4, 1 } ) ).description
                     == "DoIP entity status response, DoIP gateway, Open sockets 1/4" );
            REQUIRE( overUdp( doip( 0x4002, { 0x01, 4, 1, 0, 0, 0x10, 0 } ) ).description
                     == "DoIP entity status response, DoIP node, Open sockets 1/4, Max data "
                        "size 4096" );
            REQUIRE( overUdp( doip( 0x4003 ) ).description
                     == "Diagnostic power mode information request" );
            REQUIRE( overUdp( doip( 0x4004, { 0x01 } ) ).description
                     == "Diagnostic power mode information response, Ready" );
            REQUIRE( overTcp( doip( 0x0000, { 0x01 } ) ).description
                     == "Generic DoIP header NACK, Unknown payload type (0x01)" );
            REQUIRE(
                overTcp( doip( 0x8002, addressed( kEcu, kTester, { 0x00, 0x22 } ) ) ).description
                == "Diagnostic message ACK 0x1000" + kArrow + "0x0E00" );
            REQUIRE( overTcp( doip( 0x8003, addressed( kEcu, kTester, { 0x03 } ) ) ).description
                     == "Diagnostic message NACK 0x1000" + kArrow
                            + "0x0E00, Unknown target address (0x03)" );
            REQUIRE( overTcp( doip( 0x9000, { 1, 2, 3 } ) ).description
                     == "Reserved payload type 0x9000, 3 bytes" );
            REQUIRE( overTcp( doip( 0xF001, { 1 } ) ).description
                     == "Manufacturer-specific payload type 0xF001, 1 byte" );
        }
    }

    GIVEN( "a diagnostic message" )
    {
        THEN( "its source and target address and its UDS service are named" )
        {
            REQUIRE( overTcp( diagnostic( { 0x22, 0xF1, 0x90 } ) ).description
                     == "Diagnostic message 0x0E00" + kArrow
                            + "0x1000, UDS ReadDataByIdentifier 0xF190" );
        }
    }
}

SCENARIO( "The UDS service of a diagnostic message is named", "[doip][uds]" )
{
    GIVEN( "requests, positive and negative responses" )
    {
        const std::vector<std::pair<Bytes, std::string>> table = {
            { { 0x10, 0x03 }, "UDS DiagnosticSessionControl extendedDiagnosticSession" },
            { { 0x50, 0x03, 0x00, 0x32, 0x01, 0xF4 },
              "UDS Positive Response DiagnosticSessionControl extendedDiagnosticSession" },
            { { 0x11, 0x01 }, "UDS ECUReset hardReset" },
            { { 0x27, 0x01 }, "UDS SecurityAccess requestSeed 0x01" },
            { { 0x67, 0x01, 0xDE, 0xAD }, "UDS Positive Response SecurityAccess requestSeed 0x01" },
            { { 0x27, 0x02, 0xBE, 0xEF }, "UDS SecurityAccess sendKey 0x02" },
            { { 0x28, 0x03, 0x01 }, "UDS CommunicationControl disableRxAndTx" },
            { { 0x3E, 0x80 }, "UDS TesterPresent zeroSubFunction, suppress positive response" },
            { { 0x7E, 0x00 }, "UDS Positive Response TesterPresent zeroSubFunction" },
            { { 0x85, 0x02 }, "UDS ControlDTCSetting off" },
            { { 0x19, 0x02, 0xFF }, "UDS ReadDTCInformation reportDTCByStatusMask" },
            { { 0x14, 0xFF, 0xFF, 0xFF }, "UDS ClearDiagnosticInformation 0xFFFFFF" },
            { { 0x22, 0xF1, 0x90, 0xF1, 0x8C }, "UDS ReadDataByIdentifier 0xF190, 0xF18C" },
            { { 0x62, 0xF1, 0x90, 'W', 'P', '0' },
              "UDS Positive Response ReadDataByIdentifier 0xF190" },
            { { 0x2E, 0xF1, 0x98, 0x01 }, "UDS WriteDataByIdentifier 0xF198" },
            { { 0x2F, 0x40, 0x01, 0x03 }, "UDS InputOutputControlByIdentifier 0x4001" },
            { { 0x31, 0x01, 0xFF, 0x00 }, "UDS RoutineControl startRoutine 0xFF00" },
            { { 0x71, 0x01, 0xFF, 0x00, 0x00 },
              "UDS Positive Response RoutineControl startRoutine 0xFF00" },
            { { 0x34, 0x00, 0x44 }, "UDS RequestDownload" },
            { { 0x36, 0x01, 0xAA, 0xBB }, "UDS TransferData Block 1" },
            { { 0x37 }, "UDS RequestTransferExit" },
            { { 0x29, 0x00 }, "UDS Authentication deAuthenticate" },
            { { 0xBA, 0x01 }, "UDS Service 0xBA" },
            { { 0x7F, 0x22, 0x31 },
              "UDS Negative Response ReadDataByIdentifier NRC=0x31 (requestOutOfRange)" },
            { { 0x7F, 0x27, 0x35 }, "UDS Negative Response SecurityAccess NRC=0x35 (invalidKey)" },
            { { 0x7F, 0x31, 0x78 },
              "UDS Negative Response RoutineControl NRC=0x78 "
              "(requestCorrectlyReceived-ResponsePending)" },
            { { 0x7F, 0x10, 0x7E },
              "UDS Negative Response DiagnosticSessionControl NRC=0x7E "
              "(subFunctionNotSupportedInActiveSession)" },
            { { 0x7F, 0x2E, 0x33 },
              "UDS Negative Response WriteDataByIdentifier NRC=0x33 (securityAccessDenied)" },
            { { 0x7F, 0x34, 0x70 },
              "UDS Negative Response RequestDownload NRC=0x70 (uploadDownloadNotAccepted)" },
            { { 0x7F, 0x22, 0x13 },
              "UDS Negative Response ReadDataByIdentifier NRC=0x13 "
              "(incorrectMessageLengthOrInvalidFormat)" },
            { { 0x7F, 0x22, 0xF5 },
              "UDS Negative Response ReadDataByIdentifier NRC=0xF5 "
              "(vehicleManufacturerSpecificConditionsNotCorrect)" },
            { { 0x7F, 0x22, 0x60 },
              "UDS Negative Response ReadDataByIdentifier NRC=0x60 (ISOSAEReserved)" },
        };
        THEN( "each is named as ISO 14229-1 names it" )
        {
            for ( const auto& [ bytes, expected ] : table ) {
                INFO( expected );
                REQUIRE( uds( bytes ) == expected );
            }
        }
    }

    GIVEN( "a request for more data identifiers than are named" )
    {
        Bytes request{ 0x22 };
        for ( uint16_t did = 0xF180; did < 0xF188; ++did ) {
            putBE16( request, did );
        }
        THEN( "the first four are, then an ellipsis" )
        {
            REQUIRE( uds( request )
                     == "UDS ReadDataByIdentifier 0xF180, 0xF181, 0xF182, 0xF183, " + kEllipsis );
        }
    }

    GIVEN( "UDS messages that lack a parameter" )
    {
        THEN( "they are malformed" )
        {
            REQUIRE( uds( { 0x10 } ) == "UDS DiagnosticSessionControl [Malformed Packet]" );
            REQUIRE( uds( { 0x22, 0xF1 } ) == "UDS ReadDataByIdentifier [Malformed Packet]" );
            REQUIRE( uds( { 0x22, 0xF1, 0x90, 0xF1 } )
                     == "UDS ReadDataByIdentifier 0xF190 [Malformed Packet]" );
            REQUIRE( uds( { 0x31, 0x01 } )
                     == "UDS RoutineControl startRoutine [Malformed Packet]" );
            REQUIRE( uds( { 0x7F, 0x22 } )
                     == "UDS Negative Response ReadDataByIdentifier [Malformed Packet]" );
        }
    }
}

SCENARIO( "Several DoIP messages in a segment are all named", "[doip]" )
{
    GIVEN( "an alive check, a diagnostic message and its ACK in one segment" )
    {
        const auto segment = doip( 0x0007 ) + diagnostic( { 0x3E, 0x00 } )
                             + doip( 0x8002, addressed( kEcu, kTester, { 0x00 } ) );
        THEN( "all are named, joined by semicolons" )
        {
            REQUIRE( overTcp( segment ).description
                     == "Alive check request; Diagnostic message 0x0E00" + kArrow
                            + "0x1000, UDS TesterPresent zeroSubFunction; Diagnostic message ACK "
                              "0x1000"
                            + kArrow + "0x0E00" );
        }
    }

    GIVEN( "more messages than are named" )
    {
        Bytes segment;
        for ( int i = 0; i < 12; ++i ) {
            segment = segment + doip( 0x0007 );
        }
        THEN( "the first eight are, then an ellipsis" )
        {
            std::string expected;
            for ( int i = 0; i < 8; ++i ) {
                expected += "Alive check request; ";
            }
            REQUIRE( overTcp( segment ).description == expected + kEllipsis );
        }
    }

    GIVEN( "messages over TCP" )
    {
        const auto first = diagnostic( { 0x22, 0xF1, 0x90 } );
        const auto segment = first + diagnostic( { 0x3E, 0x00 } );
        THEN( "the TCP Reassembly frames them by their payload length" )
        {
            const auto whole
                = tcpMessageExtent( segment.data(), segment.size(), kTesterPort, kDoipPort );
            REQUIRE( whole.complete() );
            REQUIRE( whole.length == first.size() );
            REQUIRE( std::string( whole.label ) == "DoIP" );
            const auto cut = tcpMessageExtent( segment.data(), 10, kTesterPort, kDoipPort );
            REQUIRE( cut.needsMore );
            REQUIRE( cut.length == first.size() );
            const auto header = tcpMessageExtent( segment.data(), 5, kTesterPort, kDoipPort );
            REQUIRE( header.needsMore );
            REQUIRE( header.length == 6 );
            // A header that breaks the pattern begins no message, and no
            // other port is DoIP's.
            auto broken = segment;
            broken[ 1 ] = 0x00;
            REQUIRE( tcpMessageExtent( broken.data(), broken.size(), kTesterPort, kDoipPort ).framer
                     == 0 );
            REQUIRE( tcpMessageExtent( segment.data(), 10, kTesterPort, 13401 ).framer == 0 );
        }
    }
}

SCENARIO( "A truncated or malformed DoIP message is described as such", "[doip]" )
{
    GIVEN( "a header whose inverse version does not match, or an unknown version" )
    {
        auto inverse = diagnostic( { 0x3E, 0x00 } );
        inverse[ 1 ] = 0xFF;
        auto unknown = doip( 0x0007, {}, 0x05 );
        THEN( "it is an incorrect pattern, malformed" )
        {
            REQUIRE( overTcp( inverse ).description
                     == "Incorrect pattern format (version 0x02, inverse version 0xFF) "
                        "[Malformed Packet]" );
            REQUIRE( overUdp( unknown ).description
                     == "Incorrect pattern format (version 0x05, inverse version 0xFA) "
                        "[Malformed Packet]" );
            REQUIRE( overTcp( doip( 0x0007 ) + inverse ).description
                     == "Alive check request; Incorrect pattern format (version 0x02, inverse "
                        "version 0xFF) [Malformed Packet]" );
        }
    }

    GIVEN( "a payload length its type does not allow" )
    {
        THEN( "it is an invalid payload length, malformed, and the next message is still read" )
        {
            REQUIRE( overTcp( doip( 0x0005, { 0x0E, 0x00, 0x00 } ) ).description
                     == "Routing activation request, Invalid payload length 3 [Malformed Packet]" );
            REQUIRE( overTcp( doip( 0x0007, { 0x00 } ) + doip( 0x0007 ) ).description
                     == "Alive check request, Invalid payload length 1 [Malformed Packet]; Alive "
                        "check request" );
            REQUIRE( overTcp( doip( 0x8001, { 0x0E, 0x00, 0x10, 0x00 } ) ).description
                     == "Diagnostic message, Invalid payload length 4 [Malformed Packet]" );
        }
    }

    GIVEN( "a message cut at the snaplen or the end of the segment" )
    {
        const auto message = diagnostic( { 0x22, 0xF1, 0x90 } );
        THEN( "it is named as far as it goes, then an ellipsis" )
        {
            REQUIRE( overUdp( prefix( message, 14 ) ).description
                     == "Diagnostic message 0x0E00" + kArrow + "0x1000, UDS ReadDataByIdentifier "
                            + kEllipsis );
            REQUIRE( overUdp( prefix( message, 10 ) ).description
                     == "Diagnostic message " + kEllipsis );
            REQUIRE( overUdp( prefix( message, 6 ) ).description
                     == "Diagnostic message " + kEllipsis );
            REQUIRE( overUdp( prefix( message, 3 ) ).description == "Header " + kEllipsis );
            REQUIRE( overUdp( prefix( announcement(), 30 ) ).description
                     == "Vehicle announcement message/vehicle identification response message, "
                        "VIN WP0ZZZ99ZTS392124, Logical address 0x1000 "
                            + kEllipsis );
        }
    }

    GIVEN( "bytes on another port" )
    {
        THEN( "they are not DoIP" )
        {
            REQUIRE( overUdp( doip( 0x0001, {}, 0xFF ), 13401 ).label != "DoIP" );
            REQUIRE( overTcp( diagnostic( { 0x3E, 0x00 } ), 13401 ).label != "DoIP" );
        }
    }
}

SCENARIO( "Mangled DoIP never breaks the describer", "[doip][fuzz]" )
{
    Bytes request{ 0x0E, 0x00, 0x00, 0, 0, 0, 0 };
    Bytes response{ 0x0E, 0x00, 0x10, 0x00, 0x10, 0, 0, 0, 0 };
    const std::vector<Bytes> messages = {
        doip( 0x0001, {}, 0xFF ),
        doip( 0x0002, kEid ),
        doip( 0x0003, kVin ),
        announcement( 0x10, 0x10 ),
        doip( 0x0005, request ),
        doip( 0x0006, response ),
        doip( 0x0008, { 0x0E, 0x00 } ),
        doip( 0x4002, { 0x01, 4, 1, 0, 0, 0x10, 0 } ),
        doip( 0x4004, { 0x01 } ),
        doip( 0x0000, { 0x04 } ),
        diagnostic( { 0x22, 0xF1, 0x90, 0xF1, 0x8C } ),
        diagnostic( { 0x31, 0x81, 0xFF, 0x00 } ),
        diagnostic( { 0x7F, 0x22, 0x31 } ),
        doip( 0x8002, addressed( kEcu, kTester, { 0x00, 0x22, 0xF1, 0x90 } ) ),
        doip( 0x8003, addressed( kEcu, kTester, { 0x06 } ) ),
    };
    auto check = []( const Bytes& bytes ) {
        for ( const auto& result :
              { overUdp( bytes ), overTcp( bytes ), overTcp( bytes, 50123 ) } ) {
            REQUIRE( result.description.find( '\n' ) == std::string::npos );
            REQUIRE( result.description.size() < 4096 );
        }
        const auto extent = tcpMessageExtent( bytes.data(), bytes.size(), kTesterPort, kDoipPort );
        REQUIRE( ( extent.framer == 0 || extent.length > 0 ) );
    };

    GIVEN( "every prefix of each message" )
    {
        THEN( "each is described in one line, as DoIP" )
        {
            for ( const auto& message : messages ) {
                for ( size_t n = 0; n <= message.size(); ++n ) {
                    const auto cut = prefix( message, n );
                    check( cut );
                    if ( n > 0 ) {
                        REQUIRE( overTcp( cut ).label == "DoIP" );
                    }
                    if ( n == message.size() ) {
                        INFO( overTcp( cut ).description );
                        REQUIRE( overTcp( cut ).description.find( "Malformed" )
                                 == std::string::npos );
                        REQUIRE( overTcp( cut ).description.find( kEllipsis )
                                 == std::string::npos );
                    }
                }
            }
        }
    }

    GIVEN( "every single byte of each message set to telling values" )
    {
        THEN( "the description is one line" )
        {
            for ( const auto& message : messages ) {
                for ( size_t i = 0; i < message.size(); ++i ) {
                    for ( int value : { 0x00, 0x01, 0x02, 0x0F, 0x10, 0x7F, 0x80, 0xC0, 0xFF } ) {
                        auto mutated = message;
                        mutated[ i ] = static_cast<uint8_t>( value );
                        check( mutated );
                    }
                }
            }
        }
    }

    GIVEN( "segments of several messages with random bytes changed, cut anywhere" )
    {
        Bytes segment;
        for ( const auto& message : messages ) {
            segment = segment + message;
        }
        THEN( "the describer reads them without fault" )
        {
            std::mt19937 random( 13400 );
            for ( int round = 0; round < 5000; ++round ) {
                auto mutated = segment;
                const auto changes = random() % 8;
                for ( unsigned c = 0; c < changes; ++c ) {
                    mutated[ random() % mutated.size() ] = static_cast<uint8_t>( random() );
                }
                const auto start = random() % mutated.size();
                const Bytes from( mutated.begin() + static_cast<std::ptrdiff_t>( start ),
                                  mutated.end() );
                check( prefix( from, random() % ( from.size() + 1 ) ) );
            }
        }
    }
}
