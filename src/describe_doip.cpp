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
 * @file describe_doip.cpp
 * @brief The DoIP detector of the Payload Describer: DoIP messages
 *        (Diagnostics over IP, ISO 13400-2), every one in a datagram or
 *        segment, the UDS service (ISO 14229-1) of a diagnostic message,
 *        and their framing over TCP.
 */

#include "describe_common.h"

#include <cstdio>
#include <iterator>

namespace tcpdump::describer {

namespace {

/// The generic header: protocol version, inverse protocol version,
/// payload type, payload length.
constexpr size_t kHeaderBytes = 8;

/// Most messages named in a datagram or segment, then "…".
constexpr size_t kMaxMessages = 8;
/// Most data identifiers named in a ReadDataByIdentifier request, then "…".
constexpr size_t kMaxDids = 4;

// ── UDS (ISO 14229-1) ────────────────────────────────────────────────────

constexpr uint8_t kNegativeResponse = 0x7F;
constexpr uint8_t kResponseBit = 0x40;
/// The suppressPosRspMsgIndicationBit of a sub-function.
constexpr uint8_t kSuppressBit = 0x80;

/// The services, as ISO 14229-1 names them; null for one it does not.
const char* serviceName( uint8_t sid )
{
    switch ( sid ) {
    case 0x10:
        return "DiagnosticSessionControl";
    case 0x11:
        return "ECUReset";
    case 0x14:
        return "ClearDiagnosticInformation";
    case 0x19:
        return "ReadDTCInformation";
    case 0x22:
        return "ReadDataByIdentifier";
    case 0x23:
        return "ReadMemoryByAddress";
    case 0x24:
        return "ReadScalingDataByIdentifier";
    case 0x27:
        return "SecurityAccess";
    case 0x28:
        return "CommunicationControl";
    case 0x29:
        return "Authentication";
    case 0x2A:
        return "ReadDataByPeriodicIdentifier";
    case 0x2C:
        return "DynamicallyDefineDataIdentifier";
    case 0x2E:
        return "WriteDataByIdentifier";
    case 0x2F:
        return "InputOutputControlByIdentifier";
    case 0x31:
        return "RoutineControl";
    case 0x34:
        return "RequestDownload";
    case 0x35:
        return "RequestUpload";
    case 0x36:
        return "TransferData";
    case 0x37:
        return "RequestTransferExit";
    case 0x38:
        return "RequestFileTransfer";
    case 0x3D:
        return "WriteMemoryByAddress";
    case 0x3E:
        return "TesterPresent";
    case 0x83:
        return "AccessTimingParameter";
    case 0x84:
        return "SecuredDataTransmission";
    case 0x85:
        return "ControlDTCSetting";
    case 0x86:
        return "ResponseOnEvent";
    case 0x87:
        return "LinkControl";
    default:
        return nullptr;
    }
}

std::string serviceText( uint8_t sid )
{
    const char* name = serviceName( sid );
    return name ? std::string( name ) : "Service " + hexCode( sid );
}

/// The negative response codes, as ISO 14229-1 names them.
std::string nrcName( uint8_t nrc )
{
    switch ( nrc ) {
    case 0x10:
        return "generalReject";
    case 0x11:
        return "serviceNotSupported";
    case 0x12:
        return "subFunctionNotSupported";
    case 0x13:
        return "incorrectMessageLengthOrInvalidFormat";
    case 0x14:
        return "responseTooLong";
    case 0x21:
        return "busyRepeatRequest";
    case 0x22:
        return "conditionsNotCorrect";
    case 0x24:
        return "requestSequenceError";
    case 0x25:
        return "noResponseFromSubnetComponent";
    case 0x26:
        return "failurePreventsExecutionOfRequestedAction";
    case 0x31:
        return "requestOutOfRange";
    case 0x33:
        return "securityAccessDenied";
    case 0x34:
        return "authenticationRequired";
    case 0x35:
        return "invalidKey";
    case 0x36:
        return "exceedNumberOfAttempts";
    case 0x37:
        return "requiredTimeDelayNotExpired";
    case 0x70:
        return "uploadDownloadNotAccepted";
    case 0x71:
        return "transferDataSuspended";
    case 0x72:
        return "generalProgrammingFailure";
    case 0x73:
        return "wrongBlockSequenceCounter";
    case 0x78:
        return "requestCorrectlyReceived-ResponsePending";
    case 0x7E:
        return "subFunctionNotSupportedInActiveSession";
    case 0x7F:
        return "serviceNotSupportedInActiveSession";
    case 0x81:
        return "rpmTooHigh";
    case 0x82:
        return "rpmTooLow";
    case 0x83:
        return "engineIsRunning";
    case 0x84:
        return "engineIsNotRunning";
    case 0x85:
        return "engineRunTimeTooLow";
    case 0x86:
        return "temperatureTooHigh";
    case 0x87:
        return "temperatureTooLow";
    case 0x88:
        return "vehicleSpeedTooHigh";
    case 0x89:
        return "vehicleSpeedTooLow";
    case 0x8A:
        return "throttle/PedalTooHigh";
    case 0x8B:
        return "throttle/PedalTooLow";
    case 0x8C:
        return "transmissionRangeNotInNeutral";
    case 0x8D:
        return "transmissionRangeNotInGear";
    case 0x8F:
        return "brakeSwitch(es)NotClosed";
    case 0x90:
        return "shifterLeverNotInPark";
    case 0x91:
        return "torqueConverterClutchLocked";
    case 0x92:
        return "voltageTooHigh";
    case 0x93:
        return "voltageTooLow";
    case 0x94:
        return "resourceTemporarilyNotAvailable";
    default:
        if ( nrc >= 0x38 && nrc <= 0x4F ) {
            return "reservedByExtendedDataLinkSecurityDocument";
        }
        if ( nrc >= 0xF0 && nrc <= 0xFE ) {
            return "vehicleManufacturerSpecificConditionsNotCorrect";
        }
        return "ISOSAEReserved";
    }
}

/// A name from a table indexed by the sub-function, if it has one.
template <size_t N>
const char* fromTable( const char* const ( &names )[ N ], uint8_t value )
{
    return value < N ? names[ value ] : nullptr;
}

/// The sub-function of a service, without its suppress bit, as ISO
/// 14229-1 names it; its number for one it does not.
std::string subFunctionName( uint8_t sid, uint8_t sf )
{
    static const char* const kSessions[]
        = { nullptr, "defaultSession", "programmingSession", "extendedDiagnosticSession",
            "safetySystemDiagnosticSession" };
    static const char* const kResets[] = { nullptr,
                                           "hardReset",
                                           "keyOffOnReset",
                                           "softReset",
                                           "enableRapidPowerShutDown",
                                           "disableRapidPowerShutDown" };
    static const char* const kDtcInformation[] = { nullptr,
                                                   "reportNumberOfDTCByStatusMask",
                                                   "reportDTCByStatusMask",
                                                   "reportDTCSnapshotIdentification",
                                                   "reportDTCSnapshotRecordByDTCNumber",
                                                   "reportDTCStoredDataByRecordNumber",
                                                   "reportDTCExtDataRecordByDTCNumber",
                                                   "reportNumberOfDTCBySeverityMaskRecord",
                                                   "reportDTCBySeverityMaskRecord",
                                                   "reportSeverityInformationOfDTC",
                                                   "reportSupportedDTC",
                                                   "reportFirstTestFailedDTC",
                                                   "reportFirstConfirmedDTC",
                                                   "reportMostRecentTestFailedDTC",
                                                   "reportMostRecentConfirmedDTC" };
    static const char* const kCommunication[]
        = { "enableRxAndTx",
            "enableRxAndDisableTx",
            "disableRxAndEnableTx",
            "disableRxAndTx",
            "enableRxAndDisableTxWithEnhancedAddressInformation",
            "enableRxAndTxWithEnhancedAddressInformation" };
    static const char* const kAuthentication[] = { "deAuthenticate",
                                                   "verifyCertificateUnidirectional",
                                                   "verifyCertificateBidirectional",
                                                   "proofOfOwnership",
                                                   "transmitCertificate",
                                                   "requestChallengeForAuthentication",
                                                   "verifyProofOfOwnershipUnidirectional",
                                                   "verifyProofOfOwnershipBidirectional",
                                                   "authenticationConfiguration" };
    static const char* const kDynamicDefinitions[]
        = { nullptr, "defineByIdentifier", "defineByMemoryAddress",
            "clearDynamicallyDefinedDataIdentifier" };
    static const char* const kRoutines[]
        = { nullptr, "startRoutine", "stopRoutine", "requestRoutineResults" };
    static const char* const kTesterPresent[] = { "zeroSubFunction" };
    static const char* const kAccessTiming[]
        = { nullptr, "readExtendedTimingParameterSet", "setTimingParametersToDefaultValues",
            "readCurrentlyActiveTimingParameters", "setTimingParametersToGivenValues" };
    static const char* const kDtcSetting[] = { nullptr, "on", "off" };
    static const char* const kLinkControl[]
        = { nullptr, "verifyModeTransitionWithFixedParameter",
            "verifyModeTransitionWithSpecificParameter", "transitionMode" };

    const char* name = nullptr;
    switch ( sid ) {
    case 0x10:
        name = fromTable( kSessions, sf );
        break;
    case 0x11:
        name = fromTable( kResets, sf );
        break;
    case 0x19:
        name = sf == 0x14   ? "reportDTCFaultDetectionCounter"
               : sf == 0x15 ? "reportDTCWithPermanentStatus"
                            : fromTable( kDtcInformation, sf );
        break;
    case 0x27:
        if ( sf != 0 && sf != 0x7F ) {
            return ( ( sf & 1 ) ? "requestSeed " : "sendKey " ) + hexCode( sf );
        }
        break;
    case 0x28:
        name = fromTable( kCommunication, sf );
        break;
    case 0x29:
        name = fromTable( kAuthentication, sf );
        break;
    case 0x2C:
        name = fromTable( kDynamicDefinitions, sf );
        break;
    case 0x31:
        name = fromTable( kRoutines, sf );
        break;
    case 0x3E:
        name = fromTable( kTesterPresent, sf );
        break;
    case 0x83:
        name = fromTable( kAccessTiming, sf );
        break;
    case 0x85:
        name = fromTable( kDtcSetting, sf );
        break;
    case 0x87:
        name = fromTable( kLinkControl, sf );
        break;
    default:
        break;
    }
    return name ? std::string( name ) : "subFunction " + hexCode( sf );
}

/// The services whose first parameter is a sub-function.
bool hasSubFunction( uint8_t sid )
{
    switch ( sid ) {
    case 0x10:
    case 0x11:
    case 0x19:
    case 0x27:
    case 0x28:
    case 0x29:
    case 0x2C:
    case 0x31:
    case 0x3E:
    case 0x83:
    case 0x85:
    case 0x86:
    case 0x87:
        return true;
    default:
        return false;
    }
}

/// What follows the service ID of a request or positive response of
/// @p sid: its sub-function, data identifiers, routine and the like.
/// A parameter missing from a whole message makes it malformed; one
/// beyond the captured bytes is left out.
std::string parametersText( uint8_t sid, bool response, FieldReader data )
{
    std::string text;
    bool missing = false;
    if ( hasSubFunction( sid ) ) {
        uint8_t sf = 0;
        if ( !data.u8( sf ) ) {
            missing = true;
        }
        else {
            // ReadDTCInformation has no suppress bit; a response never sets it.
            const bool suppress = !response && sid != 0x19 && ( sf & kSuppressBit ) != 0;
            text += " " + subFunctionName( sid, suppress ? sf & ~kSuppressBit : sf );
            if ( sid == 0x31 ) {
                uint16_t routine = 0;
                if ( data.u16( routine ) ) {
                    text += " " + id16( routine );
                }
                else {
                    missing = true;
                }
            }
            if ( suppress ) {
                text += ", suppress positive response";
            }
        }
    }
    else if ( sid == 0x22 && !response ) {
        // Every data identifier of a request; a response's data has no
        // lengths to find any but the first by.
        std::vector<std::string> dids;
        uint16_t did = 0;
        size_t count = 0;
        while ( data.u16( did ) ) {
            if ( ++count <= kMaxDids + 1 ) {
                dids.push_back( id16( did ) );
            }
        }
        missing = dids.empty() || data.remaining() != 0;
        if ( !dids.empty() ) {
            text += " " + joinNames( std::move( dids ), kMaxDids );
        }
    }
    else if ( sid == 0x22 || sid == 0x24 || sid == 0x2E || sid == 0x2F ) {
        uint16_t did = 0;
        if ( data.u16( did ) ) {
            text += " " + id16( did );
        }
        else {
            missing = true;
        }
    }
    else if ( sid == 0x14 && !response ) {
        uint32_t group = 0;
        if ( data.u24( group ) ) {
            char buf[ 12 ];
            std::snprintf( buf, sizeof( buf ), "0x%06X", group );
            text += std::string( " " ) + buf;
        }
        else {
            missing = true;
        }
    }
    else if ( sid == 0x36 ) {
        uint8_t block = 0;
        if ( data.u8( block ) ) {
            text += " Block " + std::to_string( block );
        }
        else {
            missing = true;
        }
    }
    if ( missing && data.complete() ) {
        text += kMalformed;
    }
    return text;
}

/// The UDS message a diagnostic message carries: "UDS ReadDataByIdentifier
/// 0xF190", "UDS Positive Response …", "UDS Negative Response … NRC=0x31
/// (requestOutOfRange)"; empty if not one byte of it was captured.
std::string udsText( FieldReader data )
{
    uint8_t sid = 0;
    if ( !data.u8( sid ) ) {
        return {};
    }
    if ( sid == kNegativeResponse ) {
        std::string text = "UDS Negative Response";
        uint8_t requested = 0;
        uint8_t nrc = 0;
        if ( !data.u8( requested ) ) {
            return text + ( data.complete() ? kMalformed : "" );
        }
        text += " " + serviceText( requested );
        if ( !data.u8( nrc ) ) {
            return text + ( data.complete() ? kMalformed : "" );
        }
        return text + " NRC=" + hexCode( nrc ) + " (" + nrcName( nrc ) + ")";
    }
    const bool response = ( sid & kResponseBit ) != 0;
    const uint8_t service = response ? static_cast<uint8_t>( sid & ~kResponseBit ) : sid;
    return std::string( response ? "UDS Positive Response " : "UDS " ) + serviceText( service )
           + parametersText( service, response, data );
}

// ── DoIP (ISO 13400-2) ───────────────────────────────────────────────────

/// The protocol versions: ISO 13400-2 of 2010, 2012, 2019 and 2019/AMD1,
/// and 0xFF, the default of a vehicle identification request.
bool knownVersion( uint8_t version )
{
    return ( version >= 0x01 && version <= 0x04 ) || version == 0xFF;
}

/// The header keeps to its pattern: a known version, followed by its
/// inverse.
bool patternValid( const uint8_t* p )
{
    return knownVersion( p[ 0 ] ) && p[ 1 ] == static_cast<uint8_t>( ~p[ 0 ] );
}

/// The payload types, as Wireshark names them after ISO 13400-2; null
/// for one that is none.
const char* payloadTypeName( uint16_t type )
{
    switch ( type ) {
    case 0x0000:
        return "Generic DoIP header NACK";
    case 0x0001:
        return "Vehicle identification request";
    case 0x0002:
        return "Vehicle identification request with EID";
    case 0x0003:
        return "Vehicle identification request with VIN";
    case 0x0004:
        return "Vehicle announcement message/vehicle identification response message";
    case 0x0005:
        return "Routing activation request";
    case 0x0006:
        return "Routing activation response";
    case 0x0007:
        return "Alive check request";
    case 0x0008:
        return "Alive check response";
    case 0x4001:
        return "DoIP entity status request";
    case 0x4002:
        return "DoIP entity status response";
    case 0x4003:
        return "Diagnostic power mode information request";
    case 0x4004:
        return "Diagnostic power mode information response";
    case 0x8001:
        return "Diagnostic message";
    case 0x8002:
        return "Diagnostic message ACK";
    case 0x8003:
        return "Diagnostic message NACK";
    default:
        return nullptr;
    }
}

std::string payloadTypeText( uint16_t type )
{
    if ( const char* name = payloadTypeName( type ) ) {
        return name;
    }
    return ( type >= 0xF000 ? "Manufacturer-specific payload type " : "Reserved payload type " )
           + id16( type );
}

/// The payload length ISO 13400-2 allows a known payload type: fixed, one
/// of two (with or without an optional field), or at least the address
/// part and a byte.
bool lengthAllowed( uint16_t type, uint32_t length )
{
    switch ( type ) {
    case 0x0000:
    case 0x4004:
        return length == 1;
    case 0x0001:
    case 0x0007:
    case 0x4001:
    case 0x4003:
        return length == 0;
    case 0x0002:
        return length == 6;
    case 0x0003:
        return length == 17;
    case 0x0004:
        return length == 32 || length == 33;
    case 0x0005:
        return length == 7 || length == 11;
    case 0x0006:
        return length == 9 || length == 13;
    case 0x0008:
        return length == 2;
    case 0x4002:
        return length == 3 || length == 7;
    case 0x8001:
    case 0x8002:
    case 0x8003:
        return length >= 5;
    default:
        return true;
    }
}

/// A code with its meaning: "Unknown target address (0x03)".
std::string coded( const char* name, uint8_t code )
{
    return std::string( name ) + " (" + hexCode( code ) + ")";
}

std::string genericNackText( uint8_t code )
{
    static const char* const kNames[]
        = { "Incorrect pattern format", "Unknown payload type", "Message too large",
            "Out of memory", "Invalid payload length" };
    const char* name = fromTable( kNames, code );
    return name ? coded( name, code ) : "NACK code " + hexCode( code );
}

std::string activationTypeText( uint8_t type )
{
    switch ( type ) {
    case 0x00:
        return "Default";
    case 0x01:
        return "WWH-OBD";
    case 0xE0:
        return "Central security";
    default:
        return ( type > 0xE0 ? "OEM-specific " : "Reserved " ) + hexCode( type );
    }
}

std::string activationResponseText( uint8_t code )
{
    static const char* const kDenied[] = {
        "Routing activation denied due to unknown source address",
        "Routing activation denied because all concurrently supported TCP_DATA sockets are "
        "registered and active",
        "Routing activation denied because an SA different from the table connection entry was "
        "received on the already activated TCP_DATA socket",
        "Routing activation denied because the SA is already registered and active on a "
        "different TCP_DATA socket",
        "Routing activation denied due to missing authentication",
        "Routing activation denied due to rejected confirmation",
        "Routing activation denied due to unsupported routing activation type",
        "Routing activation denied due to request for encrypted connection via TLS",
    };
    if ( const char* name = fromTable( kDenied, code ) ) {
        return coded( name, code );
    }
    if ( code == 0x10 ) {
        return coded( "Routing successfully activated", code );
    }
    if ( code == 0x11 ) {
        return coded( "Routing will be activated; confirmation required", code );
    }
    return "Response code " + hexCode( code );
}

std::string diagnosticNackText( uint8_t code )
{
    static const char* const kNames[] = { nullptr,
                                          nullptr,
                                          "Invalid source address",
                                          "Unknown target address",
                                          "Diagnostic message too large",
                                          "Out of memory",
                                          "Target unreachable",
                                          "Unknown network",
                                          "Transport protocol error" };
    const char* name = fromTable( kNames, code );
    return name ? coded( name, code ) : "NACK code " + hexCode( code );
}

/// The payload of a message of a known type, after its name; @p body
/// holds as much of it as was captured.  Fields beyond the captured bytes
/// are left out.
std::string payloadText( uint16_t type, FieldReader body )
{
    std::string text;
    uint8_t code = 0;
    uint16_t source = 0;
    uint16_t target = 0;
    switch ( type ) {
    case 0x0000:
        if ( body.u8( code ) ) {
            text += ", " + genericNackText( code );
        }
        break;
    case 0x0002:
        if ( body.remaining() >= 6 ) {
            text += ", EID " + formatMac( body.here() );
        }
        break;
    case 0x0003:
        if ( body.remaining() >= 17 ) {
            text += ", VIN " + escapeBytes( body.here(), 17, false );
        }
        break;
    case 0x0004: {
        if ( body.remaining() < 17 ) {
            break;
        }
        text += ", VIN " + escapeBytes( body.here(), 17, false );
        body.skip( 17 );
        if ( !body.u16( source ) ) {
            break;
        }
        text += ", Logical address " + id16( source );
        if ( body.remaining() < 6 ) {
            break;
        }
        text += ", EID " + formatMac( body.here() );
        body.skip( 6 );
        if ( body.remaining() < 6 ) {
            break;
        }
        text += ", GID " + formatMac( body.here() );
        body.skip( 6 );
        if ( body.u8( code ) && code != 0x00 ) {
            text += code == 0x10 ? std::string( ", Routing activation required to initiate "
                                                "central security" )
                                 : ", Further action " + hexCode( code );
        }
        if ( body.u8( code ) && code != 0x00 ) {
            text += code == 0x10 ? std::string( ", VIN/GID not synchronized" )
                                 : ", VIN/GID sync status " + hexCode( code );
        }
        break;
    }
    case 0x0005:
        if ( body.u16( source ) ) {
            text += ", Source " + id16( source );
            if ( body.u8( code ) ) {
                text += ", Activation type " + activationTypeText( code );
            }
        }
        break;
    case 0x0006:
        if ( body.u16( target ) ) {
            text += ", Tester " + id16( target );
            if ( body.u16( source ) ) {
                text += ", Entity " + id16( source );
                if ( body.u8( code ) ) {
                    text += ", " + activationResponseText( code );
                }
            }
        }
        break;
    case 0x0008:
        if ( body.u16( source ) ) {
            text += ", Source " + id16( source );
        }
        break;
    case 0x4002: {
        uint8_t maxSockets = 0;
        uint8_t openSockets = 0;
        uint32_t maxDataSize = 0;
        if ( body.u8( code ) ) {
            text += code == 0x00   ? std::string( ", DoIP gateway" )
                    : code == 0x01 ? std::string( ", DoIP node" )
                                   : ", Node type " + hexCode( code );
            if ( body.u8( maxSockets ) && body.u8( openSockets ) ) {
                text += ", Open sockets " + std::to_string( openSockets ) + "/"
                        + std::to_string( maxSockets );
                if ( body.u32( maxDataSize ) ) {
                    text += ", Max data size " + std::to_string( maxDataSize );
                }
            }
        }
        break;
    }
    case 0x4004:
        if ( body.u8( code ) ) {
            text += code == 0x00   ? std::string( ", Not ready" )
                    : code == 0x01 ? std::string( ", Ready" )
                    : code == 0x02 ? std::string( ", Not supported" )
                                   : ", Power mode " + hexCode( code );
        }
        break;
    case 0x8001:
    case 0x8002:
    case 0x8003:
        if ( !body.u16( source ) || !body.u16( target ) ) {
            break;
        }
        text += " " + id16( source ) + " \xe2\x86\x92 " + id16( target );
        if ( type == 0x8001 ) {
            const auto uds = udsText( body );
            if ( !uds.empty() ) {
                text += ", " + uds;
            }
        }
        else if ( body.u8( code ) ) {
            if ( type == 0x8003 ) {
                text += ", " + diagnosticNackText( code );
            }
            else if ( code != 0x00 ) {
                text += ", ACK code " + hexCode( code );
            }
        }
        break;
    default:
        break;
    }
    return text;
}

/// One message, as far as it was read.
struct Message {
    std::string text;
    bool last = false;   ///< No message can follow it in these bytes
    uint64_t length = 0; ///< The bytes it takes, header and all
};

/// The message at @p p, of which @p len bytes were captured.
Message readMessage( const uint8_t* p, size_t len )
{
    Message m;
    m.last = true;
    if ( len >= 2 && !patternValid( p ) ) {
        m.text = "Incorrect pattern format (version " + hexCode( p[ 0 ] ) + ", inverse version "
                 + hexCode( p[ 1 ] ) + ")" + kMalformed;
        return m;
    }
    if ( len < 4 ) {
        m.text = "Header " + kEllipsis;
        return m;
    }
    const uint16_t type = readBE16( p + 2 );
    m.text = payloadTypeText( type );
    if ( len < kHeaderBytes ) {
        m.text += " " + kEllipsis;
        return m;
    }
    const uint32_t length = readBE32( p + 4 );
    m.length = kHeaderBytes + uint64_t{ length };
    const bool whole = len >= m.length;
    m.last = !whole;
    if ( !lengthAllowed( type, length ) ) {
        m.text += ", Invalid payload length " + std::to_string( length ) + kMalformed;
        return m;
    }
    const size_t captured
        = whole ? static_cast<size_t>( length ) : len - kHeaderBytes; // < length if cut
    const FieldReader body( p + kHeaderBytes, captured, whole );
    if ( payloadTypeName( type ) ) {
        m.text += payloadText( type, body );
    }
    else {
        m.text += ", " + std::to_string( length ) + " byte" + ( length == 1 ? "" : "s" );
    }
    if ( !whole ) {
        m.text += " " + kEllipsis;
    }
    return m;
}

} // namespace

std::string detectDoip( const uint8_t* payload, size_t len )
{
    std::string text;
    size_t count = 0;
    size_t at = 0;
    while ( at < len ) {
        if ( ++count > kMaxMessages ) {
            text += "; " + kEllipsis;
            break;
        }
        const auto message = readMessage( payload + at, len - at );
        text += ( text.empty() ? "" : "; " ) + message.text;
        if ( message.last ) {
            break;
        }
        at += static_cast<size_t>( message.length ); // whole, so within len
    }
    return text;
}

std::optional<size_t> frameDoipMessage( const uint8_t* payload, size_t len )
{
    if ( len >= 2 && !patternValid( payload ) ) {
        return std::nullopt; // no message: described as it is
    }
    if ( len < kHeaderBytes ) {
        return len + 1;
    }
    const uint64_t length = kHeaderBytes + uint64_t{ readBE32( payload + 4 ) };
    if ( length > SIZE_MAX ) {
        return SIZE_MAX;
    }
    return static_cast<size_t>( length );
}

} // namespace tcpdump::describer
