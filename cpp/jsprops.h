// jsprops.h — Unicode property tables backing jsre's \p{...} escapes.
#ifndef dship_JSPROPS_H
#define dship_JSPROPS_H

#include <cstdint>
#include <string>
#include <vector>

namespace dship {

struct PropRange {
    uint32_t lo, hi;
};

// Returns the code point ranges of a supported property name
// (General_Category shorthands/full names plus White_Space, Alphabetic,
// Any, ASCII). Returns false for unsupported names.
bool propertyRangesFor(const std::string& name, std::vector<PropRange>& out);

}  // namespace dship

#endif  // dship_JSPROPS_H
