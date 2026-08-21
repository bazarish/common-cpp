// Bazarish project (c) 2026
#include "bazarish/SelfHostedCaptcha.hpp"

#include "bazarish/Hmac.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <nlohmann/json.hpp>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <map>
#include <numbers>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace bazarish::service {

namespace {

// Defaults for the factory parameters.
constexpr int kDefaultCodeLength = 5;
constexpr std::int64_t kDefaultWindowSeconds = 300;

// No ambiguous glyphs (no I, O, 0, 1).
const char* const kAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
constexpr std::size_t kAlphabetSize = 32;

// A pool of random bytes, refilled as it drains: drawing one number at a time
// from the CSPRNG would cost far more than the drawing itself.
class RandomStream {
public:
    double uniform(const double low, const double high)
    {
        const double share = static_cast<double>(next16()) / static_cast<double>(kUnsigned16Max);
        return low + share * (high - low);
    }

    std::size_t below(const std::size_t bound) { return next16() % bound; }

    bool chance(const double probability) { return uniform(0.0, 1.0) < probability; }

private:
    static constexpr std::size_t kPoolBytes = 256;
    static constexpr unsigned kByteValues = 256;
    static constexpr unsigned kUnsigned16Max = 65535;

    unsigned next16()
    {
        const unsigned high = nextByte();
        return high * kByteValues + nextByte();
    }

    unsigned nextByte()
    {
        if (position_ >= pool_.size()) {
            pool_ = randomBytes(kPoolBytes);
            position_ = 0;
        }
        return pool_[position_++];
    }

    Bytes pool_;
    std::size_t position_ = 0;
};

struct Point {
    double x = 0.0;
    double y = 0.0;
};

using Stroke = std::vector<Point>;
using Glyph = std::vector<Stroke>;

// The box every glyph below is drawn on, in its own units.
constexpr double kGlyphUnitsX = 10.0;
constexpr double kGlyphUnitsY = 14.0;

// A stroke font for the captcha alphabet. The characters are drawn as
// polylines and never written as text, because a character in the markup is an
// answer that reads out with a regular expression - no vision, no effort.
const std::map<char, Glyph>& strokeFont()
{
    static const std::map<char, Glyph> kFont = {
        {'A', {{{0, 14}, {5, 0}, {10, 14}}, {{2, 9}, {8, 9}}}},
        {'B', {{{0, 0}, {0, 14}}, {{0, 0}, {6, 0}, {9, 2}, {9, 5}, {6, 7}, {0, 7}},
                  {{0, 7}, {7, 7}, {10, 9}, {10, 12}, {7, 14}, {0, 14}}}},
        {'C', {{{10, 3}, {8, 1}, {5, 0}, {2, 2}, {0, 7}, {2, 12}, {5, 14}, {8, 13}, {10, 11}}}},
        {'D', {{{0, 0}, {0, 14}}, {{0, 0}, {5, 0}, {9, 3}, {10, 7}, {9, 11}, {5, 14}, {0, 14}}}},
        {'E', {{{10, 0}, {0, 0}, {0, 14}, {10, 14}}, {{0, 7}, {7, 7}}}},
        {'F', {{{10, 0}, {0, 0}, {0, 14}}, {{0, 7}, {7, 7}}}},
        {'G', {{{10, 3}, {8, 1}, {5, 0}, {2, 2}, {0, 7}, {2, 12}, {5, 14}, {8, 13}, {10, 10}},
                  {{10, 10}, {10, 8}, {6, 8}}}},
        {'H', {{{0, 0}, {0, 14}}, {{10, 0}, {10, 14}}, {{0, 7}, {10, 7}}}},
        {'J', {{{10, 0}, {10, 10}, {8, 13}, {5, 14}, {2, 13}, {0, 10}}}},
        {'K', {{{0, 0}, {0, 14}}, {{10, 0}, {0, 8}}, {{3, 6}, {10, 14}}}},
        {'L', {{{0, 0}, {0, 14}, {9, 14}}}},
        {'M', {{{0, 14}, {0, 0}, {5, 8}, {10, 0}, {10, 14}}}},
        {'N', {{{0, 14}, {0, 0}, {10, 14}, {10, 0}}}},
        {'P', {{{0, 14}, {0, 0}, {6, 0}, {9, 2}, {9, 5}, {6, 7}, {0, 7}}}},
        {'Q', {{{5, 0}, {2, 2}, {0, 7}, {2, 12}, {5, 14}, {8, 12}, {10, 7}, {8, 2}, {5, 0}},
                  {{6, 10}, {10, 14}}}},
        {'R', {{{0, 14}, {0, 0}, {6, 0}, {9, 2}, {9, 5}, {6, 7}, {0, 7}}, {{5, 7}, {10, 14}}}},
        {'S', {{{10, 2}, {7, 0}, {3, 0}, {0, 3}, {2, 6}, {8, 8}, {10, 11}, {7, 14}, {3, 14},
                  {0, 12}}}},
        {'T', {{{0, 0}, {10, 0}}, {{5, 0}, {5, 14}}}},
        {'U', {{{0, 0}, {0, 10}, {2, 13}, {5, 14}, {8, 13}, {10, 10}, {10, 0}}}},
        {'V', {{{0, 0}, {5, 14}, {10, 0}}}},
        {'W', {{{0, 0}, {2, 14}, {5, 6}, {8, 14}, {10, 0}}}},
        {'X', {{{0, 0}, {10, 14}}, {{10, 0}, {0, 14}}}},
        {'Y', {{{0, 0}, {5, 7}, {10, 0}}, {{5, 7}, {5, 14}}}},
        {'Z', {{{0, 0}, {10, 0}, {0, 14}, {10, 14}}}},
        {'2', {{{0, 3}, {3, 0}, {7, 0}, {10, 3}, {9, 6}, {0, 14}, {10, 14}}}},
        {'3', {{{0, 2}, {3, 0}, {7, 0}, {10, 2}, {8, 6}, {4, 7}},
                  {{5, 7}, {9, 8}, {10, 11}, {8, 14}, {3, 14}, {0, 12}}}},
        {'4', {{{7, 14}, {7, 0}, {0, 9}, {10, 9}}}},
        {'5', {{{10, 0}, {2, 0}, {1, 6}},
                  {{1, 6}, {5, 5}, {9, 7}, {10, 10}, {8, 13}, {4, 14}, {1, 13}}}},
        {'6', {{{9, 1}, {6, 0}, {3, 2}, {1, 6}, {1, 10}},
                  {{1, 10}, {2, 13}, {5, 14}, {8, 13}, {9, 10}, {7, 7}, {4, 7}, {1, 10}}}},
        {'7', {{{0, 0}, {10, 0}, {4, 14}}}},
        {'8', {{{5, 0}, {2, 1}, {2, 4}, {5, 7}, {8, 4}, {8, 1}, {5, 0}},
                  {{5, 7}, {1, 9}, {1, 12}, {5, 14}, {9, 12}, {9, 9}, {5, 7}}}},
        {'9', {{{9, 4}, {8, 1}, {5, 0}, {2, 1}, {1, 4}, {3, 7}, {7, 7}, {9, 4}},
                  {{9, 4}, {9, 9}, {7, 13}, {3, 14}, {1, 13}}}},
    };
    return kFont;
}

// The canvas the code is drawn on, and how hard every character is bent on it.
constexpr double kCanvasHeight = 64.0;
constexpr double kMarginX = 16.0;
constexpr double kAdvanceX = 40.0;
constexpr double kGlyphHeightMin = 30.0;
constexpr double kGlyphHeightMax = 38.0;
constexpr double kRotationMaxDegrees = 14.0;
constexpr double kHalfTurnDegrees = 180.0;
constexpr double kFullTurnRadians = 2.0 * std::numbers::pi;
constexpr double kShearMax = 0.2;
constexpr double kJitterMax = 1.2;
constexpr double kBaselineShiftMax = 4.0;
constexpr double kStrokeWidthMin = 2.0;
constexpr double kStrokeWidthMax = 2.8;

// Strokes that belong to no character. They carry the same weight and the same
// look as the glyphs, so a reader cannot sort signal from noise by style - but
// they run long and straight, so a human does not mistake one for a character.
constexpr std::size_t kNoiseStrokesMin = 2;
constexpr std::size_t kNoiseStrokesMax = 3;
constexpr std::size_t kNoiseSegmentsMin = 1;
constexpr std::size_t kNoiseSegmentsMax = 2;
constexpr double kNoiseStepMin = 18.0;
constexpr double kNoiseStepMax = 48.0;
constexpr std::size_t kWaveStrokes = 1;
constexpr std::size_t kWavePoints = 26;
constexpr double kWaveAmplitudeMin = 5.0;
constexpr double kWaveAmplitudeMax = 9.0;
constexpr double kWavePeriodsMin = 1.5;
constexpr double kWavePeriodsMax = 2.5;
constexpr double kWaveBandTop = 20.0;
constexpr double kWaveBandBottom = 44.0;

// A stroke long enough to be cut in two without either half becoming a dot.
constexpr std::size_t kSplitMinPoints = 4;
constexpr double kSplitProbability = 0.5;

constexpr std::size_t kNumberTextBytes = 32;

std::string number(const double value)
{
    char text[kNumberTextBytes];
    const int written = std::snprintf(text, sizeof(text), "%.1f", value);
    if (written <= 0 || static_cast<std::size_t>(written) >= sizeof(text)) {
        throw std::runtime_error("captcha coordinate does not fit");
    }
    return std::string(text, static_cast<std::size_t>(written));
}

std::string pathOf(const Stroke& stroke, const double width)
{
    std::string path = "<path d=\"M " + number(stroke.front().x) + " " + number(stroke.front().y);
    for (std::size_t i = 1; i < stroke.size(); ++i) {
        path += " L " + number(stroke[i].x) + " " + number(stroke[i].y);
    }
    path += "\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"" + number(width)
        + "\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/>";
    return path;
}

// One character placed on the canvas: scaled, rotated, sheared and jittered, so
// that two drawings of the same character never share a path.
Glyph placeGlyph(const Glyph& glyph, const double centerX, RandomStream& random)
{
    const double unit = random.uniform(kGlyphHeightMin, kGlyphHeightMax) / kGlyphUnitsY;
    const double angle
        = random.uniform(-kRotationMaxDegrees, kRotationMaxDegrees) * std::numbers::pi
        / kHalfTurnDegrees;
    const double shear = random.uniform(-kShearMax, kShearMax);
    const double centerY
        = kCanvasHeight / 2.0 + random.uniform(-kBaselineShiftMax, kBaselineShiftMax);
    const double sine = std::sin(angle);
    const double cosine = std::cos(angle);

    Glyph placed;
    placed.reserve(glyph.size());
    for (const Stroke& stroke : glyph) {
        Stroke line;
        line.reserve(stroke.size());
        for (const Point& point : stroke) {
            const double x = (point.x - kGlyphUnitsX / 2.0) * unit;
            const double y = (point.y - kGlyphUnitsY / 2.0) * unit;
            const double sheared = x + shear * y;
            line.push_back({centerX + sheared * cosine - y * sine
                                + random.uniform(-kJitterMax, kJitterMax),
                centerY + sheared * sine + y * cosine + random.uniform(-kJitterMax, kJitterMax)});
        }
        placed.push_back(std::move(line));
    }
    return placed;
}

// Cuts a stroke into pieces that meet at the seam. The drawing does not change;
// what changes is that the shape of a path stops being a fingerprint of the
// character it came from.
Glyph splitStroke(const Stroke& stroke, RandomStream& random)
{
    if (stroke.size() < kSplitMinPoints || !random.chance(kSplitProbability)) {
        return {stroke};
    }
    const auto cut = static_cast<std::ptrdiff_t>(1 + random.below(stroke.size() - 2));
    return {Stroke(stroke.begin(), stroke.begin() + cut + 1), Stroke(stroke.begin() + cut, stroke.end())};
}

Stroke noiseStroke(const double canvasWidth, RandomStream& random)
{
    Point at{random.uniform(0.0, canvasWidth), random.uniform(0.0, kCanvasHeight)};
    Stroke stroke{at};
    const std::size_t segments
        = kNoiseSegmentsMin + random.below(kNoiseSegmentsMax - kNoiseSegmentsMin + 1);
    for (std::size_t i = 0; i < segments; ++i) {
        const double angle = random.uniform(0.0, kFullTurnRadians);
        const double step = random.uniform(kNoiseStepMin, kNoiseStepMax);
        at = {at.x + std::cos(angle) * step, at.y + std::sin(angle) * step};
        stroke.push_back(at);
    }
    return stroke;
}

// A line that crosses every character, so the characters cannot be lifted out
// one connected component at a time.
Stroke waveStroke(const double canvasWidth, RandomStream& random)
{
    const double amplitude = random.uniform(kWaveAmplitudeMin, kWaveAmplitudeMax);
    const double phase = random.uniform(0.0, kFullTurnRadians);
    const double middle = random.uniform(kWaveBandTop, kWaveBandBottom);
    const double periods = random.uniform(kWavePeriodsMin, kWavePeriodsMax);

    Stroke stroke;
    stroke.reserve(kWavePoints);
    for (std::size_t i = 0; i < kWavePoints; ++i) {
        const double share = static_cast<double>(i) / static_cast<double>(kWavePoints - 1);
        stroke.push_back({share * canvasWidth,
            middle + amplitude * std::sin(phase + share * periods * kFullTurnRadians)});
    }
    return stroke;
}

// The code as a drawing: strokes only, in no meaningful order, on a transparent
// canvas that takes its colour from the page (currentColor), so an operator
// styles the captcha with the rest of the site.
std::string renderSvg(const std::string& code)
{
    RandomStream random;
    const double canvasWidth = kMarginX * 2.0 + static_cast<double>(code.size()) * kAdvanceX;

    std::vector<std::string> paths;
    for (std::size_t i = 0; i < code.size(); ++i) {
        const auto entry = strokeFont().find(code[i]);
        if (entry == strokeFont().end()) {
            throw std::runtime_error("captcha alphabet has no stroke font entry");
        }
        const double centerX = kMarginX + static_cast<double>(i) * kAdvanceX + kAdvanceX / 2.0;
        const double width = random.uniform(kStrokeWidthMin, kStrokeWidthMax);
        for (const Stroke& stroke : placeGlyph(entry->second, centerX, random)) {
            for (const Stroke& piece : splitStroke(stroke, random)) {
                paths.push_back(pathOf(piece, width));
            }
        }
    }

    const std::size_t noise
        = kNoiseStrokesMin + random.below(kNoiseStrokesMax - kNoiseStrokesMin + 1);
    for (std::size_t i = 0; i < noise; ++i) {
        paths.push_back(pathOf(noiseStroke(canvasWidth, random),
            random.uniform(kStrokeWidthMin, kStrokeWidthMax)));
    }
    for (std::size_t i = 0; i < kWaveStrokes; ++i) {
        paths.push_back(pathOf(waveStroke(canvasWidth, random),
            random.uniform(kStrokeWidthMin, kStrokeWidthMax)));
    }

    // Document order must not separate the characters from the noise, nor spell
    // out the reading order.
    for (std::size_t i = paths.size(); i > 1; --i) {
        std::swap(paths[i - 1], paths[random.below(i)]);
    }

    std::string svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" "
                      "aria-label=\"captcha\" width=\""
        + number(canvasWidth) + "\" height=\"" + number(kCanvasHeight) + "\" viewBox=\"0 0 "
        + number(canvasWidth) + " " + number(kCanvasHeight) + "\">";
    for (const std::string& path : paths) {
        svg += path;
    }
    svg += "</svg>";
    return svg;
}

std::string randomCode(const int length)
{
    const Bytes random = randomBytes(static_cast<std::size_t>(length));
    std::string code;
    code.reserve(static_cast<std::size_t>(length));
    for (int i = 0; i < length; ++i) {
        code.push_back(kAlphabet[random[static_cast<std::size_t>(i)] % kAlphabetSize]);
    }
    return code;
}

std::string normalize(const std::string& input)
{
    std::string out;
    for (char c : input) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>(c - 'a' + 'A');
        }
        out.push_back(c);
    }
    return out;
}

std::string tagFor(const std::string& secret, const std::string& normalized, const std::int64_t ts)
{
    return hmacSha256Hex(secret, normalized + "\n" + std::to_string(ts));
}

}  // namespace

SelfHostedCaptcha::SelfHostedCaptcha(
    std::string secret, const int length, const std::int64_t windowSeconds)
    : secret_(std::move(secret))
    , length_(length)
    , windowSeconds_(windowSeconds)
{
}

std::string SelfHostedCaptcha::name() const
{
    return "selfhosted";
}

CaptchaChallenge SelfHostedCaptcha::issue(const std::int64_t now)
{
    const std::string code = randomCode(length_);
    const nlohmann::json id = {{"ts", now}, {"tag", tagFor(secret_, normalize(code), now)}};
    const std::string idText = id.dump();

    CaptchaChallenge challenge;
    challenge.id = toBase64(Bytes(idText.begin(), idText.end()));
    challenge.contentType = "image/svg+xml";
    challenge.body = renderSvg(code);
    return challenge;
}

bool SelfHostedCaptcha::verify(
    const std::string& id, const std::string& answer, const std::int64_t now)
{
    std::int64_t ts = 0;
    std::string tag;
    try {
        const Bytes raw = fromBase64(id);
        const nlohmann::json parsed = nlohmann::json::parse(raw.begin(), raw.end());
        ts = parsed.at("ts").get<std::int64_t>();
        tag = parsed.at("tag").get<std::string>();
    } catch (const std::exception&) {
        return false;  // malformed id
    }
    if (ts < now - windowSeconds_ || ts > now + windowSeconds_) {
        return false;
    }
    if (!constantTimeEqual(tag, tagFor(secret_, normalize(answer), ts))) {
        return false;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    pruneExpired(now);
    return consumed_.emplace(tag, ts).second;  // false when already used
}

void SelfHostedCaptcha::pruneExpired(const std::int64_t now)
{
    for (auto it = consumed_.begin(); it != consumed_.end();) {
        if (it->second < now - windowSeconds_) {
            it = consumed_.erase(it);
        } else {
            ++it;
        }
    }
}

std::unique_ptr<Captcha> makeSelfHostedCaptcha(const std::map<std::string, std::string>& params)
{
    const auto secret = params.find("secret");
    if (secret == params.end() || secret->second.empty()) {
        throw std::runtime_error("selfhosted captcha requires a 'secret' parameter");
    }
    int length = kDefaultCodeLength;
    if (const auto it = params.find("length"); it != params.end()) {
        length = std::stoi(it->second);
    }
    std::int64_t window = kDefaultWindowSeconds;
    if (const auto it = params.find("window"); it != params.end()) {
        window = std::stoll(it->second);
    }
    return std::make_unique<SelfHostedCaptcha>(secret->second, length, window);
}

}  // namespace bazarish::service
