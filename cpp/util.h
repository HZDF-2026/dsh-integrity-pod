// util.h — Node-facing utilities for the dsh-integrity-pod C++17 port:
// ISO timestamps, shell spawning with a sanitized environment, timeouts,
// output hashing, directory tree hashing and git inspection.
#ifndef dship_UTIL_H
#define dship_UTIL_H

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace dship {

// Node's Date.prototype.toISOString(): YYYY-MM-DDTHH:MM:SS.mmmZ (UTC).
std::string nowIso();

// sha256 hex digest of a byte string, like crypto.createHash('sha256').
std::string sha256Hex(const std::string& data);

// sha256 of the file's bytes; nullopt when the file does not exist.
std::optional<std::string> sha256FileIfExists(const std::string& path);

// Result of spawn(command, { shell: true, env: sanitizedEnv(...) }).
struct ShellResult {
    long long exitCode = 0;
    bool codeNull = false;   // killed by a signal: Node's close code === null
    bool timedOut = false;
    bool spawnError = false;  // child emitted an 'error' event (exit 126)
    std::string stdoutHash;
    std::string stderrHash;
    long long stdoutBytes = 0;
    long long stderrBytes = 0;
    long long durationMs = 0;
};

// Run a shell command with the bitwin/provenance sanitized environment.
// Captures up to capBytes per stream, hashing the captured prefix only.
ShellResult runShellSanitized(const std::string& command, const std::string& cwd,
                              long long timeoutMs, long long capBytes);

// Run a shell command with the inherited environment, capturing stdout text
// (for git plumbing). Returns nullopt when the command fails (exit != 0).
std::optional<std::string> runShellCapture(const std::string& command, const std::string& cwd);

// bitwin hashTree: map of forward-slash-relative path -> sha256, skipping
// .git / node_modules / .integrity directories, files <= maxFileBytes, at
// most maxFiles entries (walk order like readdir, cut at the cap).
std::map<std::string, std::string> hashTree(const std::string& root, long long maxFileBytes,
                                            size_t maxFiles);

// Path helpers mirroring node:path resolve for the tools' needs.
std::string pathResolve(const std::string& target);
std::string pathDirname(const std::string& p);
std::string cwd();

// Raw byte file IO (no newline translation, no BOM).
void writeFileBytes(const std::string& path, const std::string& data);
void appendFileBytes(const std::string& path, const std::string& data);
void mkdirRecursive(const std::string& path);
bool fileExists(const std::string& p);

// Time in milliseconds for durationMs fields.
long long nowMs();

}  // namespace dship

#endif  // dship_UTIL_H
