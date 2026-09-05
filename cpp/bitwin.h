// bitwin.h — dsh-integrity-bitwin: run a command twice under the sanitized
// deterministic environment and compare every content channel bit-for-bit.
#ifndef dship_BITWIN_H
#define dship_BITWIN_H

#include <string>
#include <stdexcept>

namespace dship {

struct BitwinRunArgs {
    std::string command;
    std::string cwdDir;     // empty -> process cwd
    bool hasTimeout = false;
    double timeoutMs = 0;    // default 120000
};

// Returns the JSON.stringify of the tool result (exact key order). Throws
// std::runtime_error with the plugin's message on invalid input.
std::string bitwinRun(const BitwinRunArgs& args);

}  // namespace dship

#endif  // dship_BITWIN_H
