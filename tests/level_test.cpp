#include "loganalyzer/level.hpp"
#include "testkit.hpp"

using loganalyzer::Level;
using loganalyzer::level_from_string;
using loganalyzer::to_string;

TEST(Level, ToStringRoundTrips) {
    for (Level l : {Level::Debug, Level::Info, Level::Warn, Level::Error}) {
        auto parsed = level_from_string(to_string(l));
        CHECK(parsed.has_value());
        CHECK(*parsed == l);
    }
}

TEST(Level, ParsingIsCaseInsensitive) {
    CHECK(level_from_string("error") == Level::Error);
    CHECK(level_from_string("WaRn") == Level::Warn);
}

TEST(Level, RejectsUnknownText) {
    CHECK(!level_from_string("").has_value());
    CHECK(!level_from_string("FATAL").has_value());
    CHECK(!level_from_string("ERRORS").has_value());
}

TEST(Level, SeverityIsOrdered) {
    CHECK(Level::Debug < Level::Info);
    CHECK(Level::Info < Level::Warn);
    CHECK(Level::Warn < Level::Error);
}
