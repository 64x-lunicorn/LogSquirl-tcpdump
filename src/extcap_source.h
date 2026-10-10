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
 * @file extcap_source.h
 * @brief The Wireshark extcap source: every extcap the user has (sshdump,
 *        androiddump, ciscodump, udpdump, randpktdump, a vendor's) as a
 *        live source, speaking Wireshark's extcap protocol.
 *
 * The source looks for executables in the extcap directories
 * (ExtcapPlaces: `$WIRESHARK_EXTCAP_DIR`, the personal and the global
 * directory of Wireshark on this OS, each with its `wireshark`
 * subdirectory) and asks each, as Wireshark does:
 *
 *     <extcap> --extcap-interfaces
 *         extcap {version=1.0}{help=…}
 *         interface {value=sshdump}{display=SSH remote capture}
 *     <extcap> --extcap-interface <if> --extcap-dlts
 *         dlt {number=1}{name=EN10MB}{display=Ethernet}
 *     <extcap> --extcap-interface <if> --extcap-config
 *         arg {number=0}{call=--remote-host}{display=Remote host}{type=string}{required=true}
 *         value {arg=3}{value=wlan0}{display=Wi-Fi}{default=true}
 *
 * Its devices are the extcaps (one whose `--extcap-interfaces` fails is
 * listed with why, and cannot be chosen); its interfaces those the chosen
 * extcap reports.  The interface's arguments become a form
 * (ExtcapOptionsWidget, extcap_options.h), whose values are LiveOptions
 * named after the interface and the argument (extcapOptionName()); a
 * password, or an argument the extcap says not to save, is a secret
 * option, never written to settings.ini.  It captures with
 *
 *     <extcap> --capture --extcap-interface <if> --fifo <pipe>
 *              [--extcap-capture-filter <filter>] [--<arg>=<value> …]
 *
 * every word one argument, never through a shell; the pipe is a FIFO (a
 * named pipe on Windows) the plugin makes and reads (PipeSource), and Stop
 * ends the extcap's process group.  The plugin passes no
 * `--extcap-control-in`/`--extcap-control-out`: an extcap's toolbar
 * controls are optional, and it captures without them.
 *
 * Every listing is bounded by a timeout and what is parsed by counts and
 * lengths: an extcap is a program of the user's, but its output is not
 * trusted to be small.
 */

#pragma once

#include "live_source.h"
#include "local_source.h"

#include <QMap>
#include <QString>
#include <QStringList>

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace tcpdump {

/// One sentence of an extcap's output: `arg {number=0}{call=--host}…`.
struct ExtcapSentence {
    QString keyword;              ///< "extcap", "interface", "dlt", "arg", "value", …
    QMap<QString, QString> items; ///< Its `{key=value}` items, keys in lower case.
};

/// The sentences of @p out, one a line; a line that is no sentence is
/// skipped.  `\}`, `\{` and `\\` in a value are its braces and backslash.
/// At most kMaxExtcapSentences, each line at most kMaxExtcapLine characters.
std::vector<ExtcapSentence> parseExtcapSentences( const QString& out );

/// The most sentences of one output that are read.
constexpr int kMaxExtcapSentences = 4096;
/// The longest line of an output that is read.
constexpr int kMaxExtcapLine = 16384;

/// An interface an extcap reports.
struct ExtcapInterface {
    QString value;   ///< What --extcap-interface takes.
    QString display; ///< What the user is shown.
};

/// What `--extcap-interfaces` says.
struct ExtcapInterfaces {
    QString version; ///< The extcap's own version, if it says.
    QString help;    ///< Its help page, if it says.
    std::vector<ExtcapInterface> interfaces;
};

/// The interfaces of `--extcap-interfaces` output @p out (at most 256; one
/// without a value, or listed before, is skipped).
ExtcapInterfaces parseExtcapInterfaces( const QString& out );

/// A link type an interface captures (`--extcap-dlts`).
struct ExtcapDlt {
    int number = 0;  ///< The DLT, e.g. 1.
    QString name;    ///< E.g. EN10MB.
    QString display; ///< E.g. Ethernet.
};

/// The link types of `--extcap-dlts` output @p out.
std::vector<ExtcapDlt> parseExtcapDlts( const QString& out );

/// The type of an extcap argument, as its form shows it.
enum class ExtcapArgType {
    String,       ///< A line of text (also a timestamp, and a type not known).
    Password,     ///< A line of text not shown, and never saved.
    Integer,      ///< A whole number.
    Unsigned,     ///< A whole number, not negative.
    Long,         ///< A whole number, 64 bits.
    Double,       ///< A number.
    Boolean,      ///< A check box, passed as --arg=true or --arg=false.
    BoolFlag,     ///< A check box, passed as --arg when checked.
    Selector,     ///< One of its values, in a drop-down list.
    Radio,        ///< One of its values, as radio buttons.
    EditSelector, ///< One of its values, or one typed.
    Multicheck,   ///< Any of its values, passed comma-separated.
    FileSelect,   ///< A file path, chosen or typed.
};

/// The ExtcapArgType of the config's `{type=…}` @p name; String for one not known.
ExtcapArgType extcapArgType( const QString& name );

/// A value of a selector, radio, editselector or multicheck argument.
struct ExtcapValue {
    QString value;          ///< What is passed.
    QString display;        ///< What the user is shown.
    QString parent;         ///< A multicheck's parent value, if it has one.
    bool isDefault = false; ///< Chosen unless the user chose otherwise.
    bool enabled = true;    ///< Whether it can be chosen.
};

/// An argument an interface takes (`--extcap-config`).
struct ExtcapArg {
    int number = 0;        ///< Its order, and what its values refer to.
    QString call;          ///< The option, e.g. --remote-host.
    QString display;       ///< Its label.
    QString tooltip;       ///< What it is, if the extcap says.
    QString placeholder;   ///< A hint shown in an empty field.
    QString defaultValue;  ///< Its value unless the user gives another.
    QString validation;    ///< A regular expression its value must match, if any.
    QString fileExtension; ///< A fileselect's file types, e.g. "Text files (*.txt)".
    QString rangeMin;      ///< A number's least value, if it has one.
    QString rangeMax;      ///< A number's greatest value, if it has one.
    ExtcapArgType type = ExtcapArgType::String;
    bool required = false;  ///< The capture needs a value.
    bool mustExist = false; ///< A fileselect's file must exist.
    /// Never saved: a password, or an argument the extcap says not to save.
    bool secret = false;
    std::vector<ExtcapValue> values; ///< A selector's, radio's or multicheck's.
};

/// The arguments of `--extcap-config` output @p out, in the order of their
/// numbers, with their values.  An argument whose call is not a long option
/// (`--name`) or is one of the protocol's own (`--fifo`, `--capture`,
/// `--extcap-…`) is skipped; at most 256 arguments and 1024 values each.
std::vector<ExtcapArg> parseExtcapConfig( const QString& out );

/// What an interface takes and gives.
struct ExtcapConfig {
    std::vector<ExtcapArg> args;
    std::vector<ExtcapDlt> dlts;
    QString error; ///< Why it could not be asked; empty if it was.
};

/**
 * The option name of @p arg for @p networkInterface: the interface,
 * percent-encoded (so that it holds no '/', ':' or '?'), ':' and the call
 * (`sshdump:--remote-host`), or '?' and the call for a boolflag
 * (`sshdump?--verbose`, "true" or "false"); a secret's after
 * kSecretOptionMark.
 */
QString extcapOptionName( const QString& networkInterface, const ExtcapArg& arg );

/// The arguments the options of @p networkInterface in @p options give, in
/// the order of their names: `--call=value` for each value not empty,
/// `--call` for a checked boolflag; secrets too.  Names of other interfaces,
/// and calls that are no long option, are skipped.
QStringList extcapArguments( const LiveOptions& options, const QString& networkInterface );

/**
 * Why the options of @p networkInterface in @p options break a rule of
 * the interface's arguments @p args, for the Start button; empty if they
 * break none: a required argument without a value (or none kept), a
 * number that is none or out of its `{range=}`, a value its
 * `{validation=}` pattern does not match as a whole, or a `{mustexist=true}`
 * file that is not there.  A check box (boolean, boolflag) breaks none.
 * The first argument, in their order, that breaks one is named.
 */
QString extcapArgumentProblem( const std::vector<ExtcapArg>& args, const LiveOptions& options,
                               const QString& networkInterface );

/// Where the extcap source looks for extcaps.
struct ExtcapPlaces {
    CaptureOs os = runningCaptureOs(); ///< Windows: .exe, .bat and .cmd files.
    /// The directories, in order; an extcap's name found in two is the first's.
    QStringList directories;

    /// This computer's: `$WIRESHARK_EXTCAP_DIR`; the personal directory
    /// (`~/.local/lib/wireshark/extcap`, `~/.config/wireshark/extcap`;
    /// `%APPDATA%\Wireshark\extcap`); Wireshark's global one
    /// (`Wireshark.app/Contents/MacOS/extcap`, `/usr/lib/<triplet>/wireshark/extcap`,
    /// `/usr/lib/wireshark/extcap`, …, `%ProgramFiles%\Wireshark\extcap`);
    /// each followed by its `wireshark` subdirectory (Wireshark 4.2 and later).
    static ExtcapPlaces forThisComputer();
};

/// Where to get extcaps, for a source that found none in @p places.
QString extcapInstallHint( const ExtcapPlaces& places );

/// Live capture through a Wireshark extcap.
class ExtcapSourceKind : public LiveSourceKind {
public:
    explicit ExtcapSourceKind( ExtcapPlaces places = ExtcapPlaces::forThisComputer() );

    /// An extcap found.
    struct Extcap {
        QString name; ///< Its file name, the device's id.
        QString path; ///< Where it is.
    };
    /// The extcaps in the directories, by name; looked for anew on each call.
    std::vector<Extcap> extcaps() const;
    /// The path of the extcap @p name, empty if it is not found.
    QString program( const QString& name ) const;

    /// The arguments and link types of @p networkInterface of the extcap
    /// @p device, at most @p timeout; on a worker thread.  The arguments
    /// are remembered for validate(), by this kind and its copies; a
    /// question that fails forgets those asked before.
    ExtcapConfig config( const QString& device, const QString& networkInterface,
                         std::chrono::milliseconds timeout ) const;

    const ExtcapPlaces& places() const
    {
        return places_;
    }

    QString id() const override;
    QString displayName() const override;
    LiveAvailability availability() const override;
    Devices devices() const override;
    QString deviceLabel() const override;
    /// Every extcap, asked for its interfaces within @p timeout in all: one
    /// that fails is listed with why.
    LiveListing listDevices( std::chrono::milliseconds timeout ) const override;
    LiveListing listInterfaces( const QString& device,
                                std::chrono::milliseconds timeout ) const override;
    /// An extcap that is there and an interface; then the rules of the
    /// interface's arguments (extcapArgumentProblem()), once config() was
    /// asked for them: until then the extcap itself says what it lacks.
    QString validate( const LiveChoice& choice ) const override;
    LiveOptionsWidget* makeOptionsWidget() const override;
    /// The capture of @p choice but its `--fifo <pipe>`, which makeSource()
    /// adds once it has made the pipe.
    ProcessCommand command( const LiveChoice& choice ) const override;
    /// A PipeSource running command() with the pipe it made.
    LiveCapture::SourceFactory makeSource( const LiveChoice& choice ) const override;

private:
    /// Run the extcap @p path with @p arguments, at most @p timeout; its
    /// stdout, or throws std::runtime_error saying why it failed.
    QString ask( const QString& path, const QStringList& arguments,
                 std::chrono::milliseconds timeout ) const;

    /// The arguments config() was told last, by extcap and interface:
    /// shared by the copies of this kind (the options widget asks through
    /// one), written on a worker thread and read on the UI thread.
    struct KnownArgs {
        std::mutex mutex;
        std::map<std::pair<QString, QString>, std::vector<ExtcapArg>> byInterface;
    };

    ExtcapPlaces places_;
    std::shared_ptr<KnownArgs> knownArgs_ = std::make_shared<KnownArgs>();
};

} // namespace tcpdump
