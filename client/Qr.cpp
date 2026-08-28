// Bazarish project (c) 2026
#include "Qr.hpp"

#include <qrencode.h>

#include <stdexcept>

namespace bazarish::client {

namespace {

// The largest standard symbol with the lowest error correction gives the most
// bytes per symbol, so the full chain needs the fewest frames. Structured
// append requires a fixed version (it cannot auto-size).
constexpr int kQrVersion = 40;
// Modules of white margin around the symbol, required for a scanner to lock.
constexpr int kQuietModules = 2;

// Two terminal columns per module keep the symbol roughly square in a cell
// grid that is taller than it is wide.
const char* const kDark = "██";
const char* const kLight = "  ";

std::string renderOne(const QrSymbol& symbol)
{
    const int width = symbol.width;
    const int span = width + 2 * kQuietModules;
    std::string out;

    const auto blankLine = [&]() {
        for (int i = 0; i < span; ++i) {
            out += kLight;
        }
        out += '\n';
    };

    for (int i = 0; i < kQuietModules; ++i) {
        blankLine();
    }
    for (int y = 0; y < width; ++y) {
        for (int i = 0; i < kQuietModules; ++i) {
            out += kLight;
        }
        for (int x = 0; x < width; ++x) {
            out += symbol.modules[y * width + x] ? kDark : kLight;
        }
        for (int i = 0; i < kQuietModules; ++i) {
            out += kLight;
        }
        out += '\n';
    }
    for (int i = 0; i < kQuietModules; ++i) {
        blankLine();
    }
    return out;
}

}  // namespace

std::vector<QrSymbol> encodeQrSymbols(const std::string& payload)
{
    QRcode_List* const list
        = QRcode_encodeString8bitStructured(payload.c_str(), kQrVersion, QR_ECLEVEL_L);
    if (list == nullptr) {
        throw std::runtime_error("QR encoding failed");
    }

    std::vector<QrSymbol> symbols;
    for (QRcode_List* entry = list; entry != nullptr; entry = entry->next) {
        if (entry->code == nullptr) {
            continue;
        }
        const QRcode* const qr = entry->code;
        QrSymbol symbol;
        symbol.width = qr->width;
        symbol.modules.resize(static_cast<std::size_t>(qr->width) * qr->width);
        for (std::size_t i = 0; i < symbol.modules.size(); ++i) {
            // The least significant bit of each module byte is the dark flag.
            symbol.modules[i] = qr->data[i] & 1;
        }
        symbols.push_back(std::move(symbol));
    }
    QRcode_List_free(list);
    return symbols;
}

std::vector<std::string> renderQrCodes(const std::string& payload)
{
    std::vector<std::string> codes;
    for (const QrSymbol& symbol : encodeQrSymbols(payload)) {
        codes.push_back(renderOne(symbol));
    }
    return codes;
}

}  // namespace bazarish::client
