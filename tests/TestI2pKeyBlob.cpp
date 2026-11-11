// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "bazarish/Bytes.hpp"
#include "bazarish/Clock.hpp"
#include "bazarish/I2pAddress.hpp"

#include "TestUtil.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>

using namespace bazarish;

namespace {

const std::string kMasterBlob
    = "e32a7544d00db4c53f5959ce076439e6cadb169351bdb2db564d916c3f1e8174b65e8538460dfb23dc4c7158"
      "f53a63ea92857704e9feaefe5e671faedaa9f11ff602aa810d7ec2ad4a9a1a3c3414a79993879bc7d011d8d8"
      "3ed865463308f7ecde612e808d77e8dc548b47e9cdefdd8121ffec47eded0de85ed04d2f8ee0940009baee55"
      "4c6aec204d1b38cb7a506854d4a1163970a988c68795b34dd675a4b051142ec2deaeba5f36bf95f4c83a26f5"
      "8b51ddde8e25fd8c08f62c1a48983f9612cc1805114987b294d1e88939aec826971dc69213561ba70400d8da"
      "dafcb68ee913b88b0462b06727c2405c03a31ea7f0bc391b2d55aca87e50444b867317d5184d51b91f1b1845"
      "935e903fc95adc702d943f1e0c778f0a02b7443fa9a509ac184d51b91f1b1845935e903fc95adc702d943f1e"
      "0c778f0a02b7443fa9a509ac184d51b91f1b1845935e903fc95adc702d943f1e0c778f0a02b7443fa9a509ac"
      "dd3a1d86d6b92cb554a55d8b153516e3adfd79ce26ce572434edda020553dccd050004000700002fd18bd7ae"
      "08efe72628009b6246b88836a5359302036523f81f39ce1a52061c12e562f393680c8a388b4ba39b6ccf4859"
      "b91a5613789f248c3ef820ecd6d118c6b73a827c71957f407294a0e4131b0760dfec9ca8b41dbec3966b005e"
      "29979c207655b3f316b29e09016082efa65f9a57433461db9a7d0e5de3d7885309ab0ea5b5ebde4d1ff55a1c"
      "a282d86a251506645872ad737f4c40d912b2786e850543167d1a5e5a41a5f3e9ef9df94b8c3dfb61beef8b97"
      "960164fd601542534c435175998d50fd764a2c705556bcd48e04d761439eb1d9127df15875ed84d5521dce8d"
      "3bb39aa66bd36ad1269a26709564da8bec196b0026d11d490b0e316f1a19468a0dc2cbacec894890c8f8e111"
      "7aa7c493671ee6a065d01c559c080d41b74db2";
const std::string kTransientBlob
    = "e32a7544d00db4c53f5959ce076439e6cadb169351bdb2db564d916c3f1e8174b65e8538460dfb23dc4c7158"
      "f53a63ea92857704e9feaefe5e671faedaa9f11ff602aa810d7ec2ad4a9a1a3c3414a79993879bc7d011d8d8"
      "3ed865463308f7ecde612e808d77e8dc548b47e9cdefdd8121ffec47eded0de85ed04d2f8ee0940009baee55"
      "4c6aec204d1b38cb7a506854d4a1163970a988c68795b34dd675a4b051142ec2deaeba5f36bf95f4c83a26f5"
      "8b51ddde8e25fd8c08f62c1a48983f9612cc1805114987b294d1e88939aec826971dc69213561ba70400d8da"
      "dafcb68ee913b88b0462b06727c2405c03a31ea7f0bc391b2d55aca87e50444b867317d5184d51b91f1b1845"
      "935e903fc95adc702d943f1e0c778f0a02b7443fa9a509ac184d51b91f1b1845935e903fc95adc702d943f1e"
      "0c778f0a02b7443fa9a509ac184d51b91f1b1845935e903fc95adc702d943f1e0c778f0a02b7443fa9a509ac"
      "dd3a1d86d6b92cb554a55d8b153516e3adfd79ce26ce572434edda020553dccd050004000700002fd18bd7ae"
      "08efe72628009b6246b88836a5359302036523f81f39ce1a52061c12e562f393680c8a388b4ba39b6ccf4859"
      "b91a5613789f248c3ef820ecd6d118c6b73a827c71957f407294a0e4131b0760dfec9ca8b41dbec3966b005e"
      "29979c207655b3f316b29e09016082efa65f9a57433461db9a7d0e5de3d7885309ab0ea5b5ebde4d1ff55a1c"
      "a282d86a251506645872ad737f4c40d912b2786e850543167d1a5e5a41a5f3e9ef9df94b8c3dfb61beef8b97"
      "960164fd601542534c435175998d50fd764a2c705556bcd48e04d761439eb1d9127df15875ed84d5521dce8d"
      "3bb39aa66bd36ad1269a26709564da8bec196b0026d11d490b0e316f1a194600000000000000000000000000"
      "00000000000000000000000000000000000000f4865700000752b579f0f68d85b1e1c1d1d155927ea2d88c0e"
      "6e42787df287382b863c24ab9077d0429a82ba0115094bbb7d5e9de9efd3b76bdc6d2b70c2313fba7186b83e"
      "03b03f14bc735b15f4d8e7f2709b9e6bc705a71c4df52cb8b5b530ed86cde6b00c3c3d7802691f743bb14915"
      "5e9667008bd685a1b8f1cb8a4de107064662272726";
const std::string kPublic
    = "4yp1RNANtMU~WVnOB2Q55srbFpNRvbLbVk2RbD8egXS2XoU4Rg37I9xMcVj1OmPqkoV3BOn-rv5eZx-u2qnxH~YC"
      "qoENfsKtSpoaPDQUp5mTh5vH0BHY2D7YZUYzCPfs3mEugI136NxUi0fpze~dgSH~7Eft7Q3oXtBNL47glAAJuu5V"
      "TGrsIE0bOMt6UGhU1KEWOXCpiMaHlbNN1nWksFEULsLerrpfNr-V9Mg6JvWLUd3ejiX9jAj2LBpImD-WEswYBRFJ"
      "h7KU0eiJOa7IJpcdxpITVhunBADY2tr8to7pE7iLBGKwZyfCQFwDox6n8Lw5Gy1VrKh-UERLhnMX1RhNUbkfGxhF"
      "k16QP8la3HAtlD8eDHePCgK3RD-ppQmsGE1RuR8bGEWTXpA~yVrccC2UPx4Md48KArdEP6mlCawYTVG5HxsYRZNe"
      "kD~JWtxwLZQ~Hgx3jwoCt0Q~qaUJrN06HYbWuSy1VKVdixU1FuOt~XnOJs5XJDTt2gIFU9zNBQAEAAcAAA==";
const std::string kB33Host = "5jzslxj2dwdnnojmwvkkkxmlcu2rny5n7v444jwok4sdj3o2aicvhxgn.b32.i2p";
constexpr std::int64_t kTransientExpires = 4102444800;
const std::string kMasterPrivateBase64
    = "4yp1RNANtMU~WVnOB2Q55srbFpNRvbLbVk2RbD8egXS2XoU4Rg37I9xMcVj1OmPqkoV3BOn-rv5eZx-u2qnxH~YC"
      "qoENfsKtSpoaPDQUp5mTh5vH0BHY2D7YZUYzCPfs3mEugI136NxUi0fpze~dgSH~7Eft7Q3oXtBNL47glAAJuu5V"
      "TGrsIE0bOMt6UGhU1KEWOXCpiMaHlbNN1nWksFEULsLerrpfNr-V9Mg6JvWLUd3ejiX9jAj2LBpImD-WEswYBRFJ"
      "h7KU0eiJOa7IJpcdxpITVhunBADY2tr8to7pE7iLBGKwZyfCQFwDox6n8Lw5Gy1VrKh-UERLhnMX1RhNUbkfGxhF"
      "k16QP8la3HAtlD8eDHePCgK3RD-ppQmsGE1RuR8bGEWTXpA~yVrccC2UPx4Md48KArdEP6mlCawYTVG5HxsYRZNe"
      "kD~JWtxwLZQ~Hgx3jwoCt0Q~qaUJrN06HYbWuSy1VKVdixU1FuOt~XnOJs5XJDTt2gIFU9zNBQAEAAcAAC~Ri9eu"
      "CO~nJigAm2JGuIg2pTWTAgNlI~gfOc4aUgYcEuVi85NoDIo4i0ujm2zPSFm5GlYTeJ8kjD74IOzW0RjGtzqCfHGV"
      "f0BylKDkExsHYN~snKi0Hb7DlmsAXimXnCB2VbPzFrKeCQFggu-mX5pXQzRh25p9Dl3j14hTCasOpbXr3k0f9Voc"
      "ooLYaiUVBmRYcq1zf0xA2RKyeG6FBUMWfRpeWkGl8-nvnflLjD37Yb7vi5eWAWT9YBVCU0xDUXWZjVD9dkoscFVW"
      "vNSOBNdhQ56x2RJ98Vh17YTVUh3OjTuzmqZr02rRJpomcJVk2ovsGWsAJtEdSQsOMW8aGUaKDcLLrOyJSJDI-OER"
      "eqfEk2ce5qBl0BxVnAgNQbdNsg==";

const std::string kSigningSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const std::string kCryptoSeed = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const std::string kSeededHost = "z24g4a5ba677htqqxyoxbxiy45f4bglh4tldbg5fbvpr3xegmqjfkmny.b32.i2p";
constexpr std::size_t kEd25519KeyBytes = 32;
constexpr std::size_t kX25519KeyBytes = 32;
// I2P common structures: a 256-byte key field, a 128-byte signing key field, then a key certificate.
constexpr std::size_t kSigningKeyEnd = 384;
constexpr std::size_t kCertTypeOffset = kSigningKeyEnd;
constexpr std::size_t kSigTypeOffset = kCertTypeOffset + 3;
constexpr std::size_t kCryptoTypeOffset = kSigTypeOffset + 2;
constexpr std::size_t kSeededBlobBytes = kCryptoTypeOffset + 2 + kX25519KeyBytes + kEd25519KeyBytes;
constexpr std::uint8_t kKeyCertificate = 5;
constexpr std::uint8_t kEd25519SigType = 7;
constexpr std::uint8_t kX25519CryptoType = 4;

}  // namespace

// An offline-signed destination whose encryption key is X25519, written by libi2pd itself.
const std::string kX25519OfflineBlob
    = "76a3d15885409bb7c21627eac4243fefbee3afa5e98b84090afb2e073ad5bbfc76a3d15885409bb7c21627ea"
      "c4243fefbee3afa5e98b84090afb2e073ad5bbfc76a3d15885409bb7c21627eac4243fefbee3afa5e98b8409"
      "0afb2e073ad5bbfc76a3d15885409bb7c21627eac4243fefbee3afa5e98b84090afb2e073ad5bbfc76a3d158"
      "85409bb7c21627eac4243fefbee3afa5e98b84090afb2e073ad5bbfc76a3d15885409bb7c21627eac4243fef"
      "bee3afa5e98b84090afb2e073ad5bbfc76a3d15885409bb7c21627eac4243fefbee3afa5e98b84090afb2e07"
      "3ad5bbfc76a3d15885409bb7c21627eac4243fefbee3afa5e98b84090afb2e073ad5bbfc76a3d15885409bb7"
      "c21627eac4243fefbee3afa5e98b84090afb2e073ad5bbfc76a3d15885409bb7c21627eac4243fefbee3afa5"
      "e98b84090afb2e073ad5bbfc76a3d15885409bb7c21627eac4243fefbee3afa5e98b84090afb2e073ad5bbfc"
      "f7506e9c4f206d39a0dea925fc5ba97bdec13f05fe3f1e5af143fcac1a4fa64c0500040007000486716f11e5"
      "5b13d6275b84937d88c1742ea3a9a1bb93db454576e8bab2c942040000000000000000000000000000000000"
      "0000000000000000000000000000006b1088ba0007fc91e90ff6b24b93264787f06b0875a97a561c14242608"
      "be5aa128f8323b069504c52f75d0c570d4703e1eab9042d24f40f3e78178f656e4e3c0d51eecc7a2465bbc9d"
      "0802eeca596a4ca74da799d32a2799e58df30a118b21645547f6f0f90b4bf9937415717c38f60e35b955a22b"
      "0b6e86534cb21c78f0135a906967e941f3";
constexpr std::int64_t kX25519OfflineExpires = 1796245690;
const std::string kX25519Host = "hxt2gnncntx3bmw4phabl44ml67r2ekts366xzex3f63iff6ttya.b32.i2p";

int main()
{
    const i2p::Keys x25519 = i2p::Keys::fromBlob(bazarish::fromHex(kX25519OfflineBlob));
    CHECK(x25519.isOffline());
    CHECK(x25519.transientExpires() == kX25519OfflineExpires);
    CHECK(i2p::routingHost(x25519.publicBase64(), false) == kX25519Host);

    const Bytes masterBlob = bazarish::fromHex(kMasterBlob);
    const i2p::Keys master = i2p::Keys::fromBlob(masterBlob);

    CHECK(master.blob() == masterBlob);
    CHECK(master.publicBase64() == kPublic);
    CHECK(master.privateBase64() == kMasterPrivateBase64);
    CHECK(!master.isOffline());
    CHECK(master.transientExpires() == 0);

    CHECK(i2p::routingHost(master.publicBase64()) == kB33Host);

    const i2p::Keys transient = i2p::Keys::fromBlob(bazarish::fromHex(kTransientBlob));
    CHECK(transient.publicBase64() == kPublic);
    CHECK(i2p::routingHost(transient.publicBase64()) == kB33Host);
    CHECK(transient.isOffline());
    CHECK(transient.transientExpires() == kTransientExpires);

    bool refused = false;
    try {
        (void)i2p::Keys::fromBlob(Bytes(masterBlob.begin(), masterBlob.begin() + 100));
    } catch (const std::exception&) {
        refused = true;
    }
    CHECK(refused);

    {
        const Bytes signingSeed = bazarish::fromHex(kSigningSeed);
        const Bytes cryptoSeed = bazarish::fromHex(kCryptoSeed);
        const i2p::Keys seeded = i2p::Keys::fromSeeds(signingSeed, cryptoSeed);
        const Bytes blob = seeded.blob();
        CHECK(i2p::Keys::fromSeeds(signingSeed, cryptoSeed).blob() == blob);
        const std::string host = i2p::routingHost(seeded.publicBase64());
        CHECK(host == kSeededHost);
        CHECK(blob.size() == kSeededBlobBytes);
        CHECK(std::all_of(blob.begin() + kX25519KeyBytes,
            blob.begin() + kSigningKeyEnd - kEd25519KeyBytes, [](const std::uint8_t b) { return b == 0; }));
        CHECK(blob[kCertTypeOffset] == kKeyCertificate);
        CHECK(blob[kSigTypeOffset] == 0 && blob[kSigTypeOffset + 1] == kEd25519SigType);
        CHECK(blob[kCryptoTypeOffset] == 0 && blob[kCryptoTypeOffset + 1] == kX25519CryptoType);
        CHECK(Bytes(blob.end() - kEd25519KeyBytes, blob.end()) == signingSeed);
        CHECK(Bytes(blob.end() - kEd25519KeyBytes - kX25519KeyBytes, blob.end() - kEd25519KeyBytes)
            == cryptoSeed);

        const i2p::Keys delegated = seeded.issueTransient(1);
        CHECK(delegated.isOffline());
        CHECK(i2p::routingHost(delegated.publicBase64()) == host);
        CHECK(delegated.b33OfflineKeysCover(nowSeconds(), delegated.transientExpires()));

        Bytes otherSigning = signingSeed;
        otherSigning.back() ^= 1;
        CHECK(i2p::routingHost(i2p::Keys::fromSeeds(otherSigning, cryptoSeed).publicBase64()) != host);
        CHECK(i2p::Keys::fromSeeds(signingSeed, otherSigning).blob() != blob);
        CHECK_THROWS(i2p::Keys::fromSeeds(Bytes(signingSeed.begin(), signingSeed.end() - 1), cryptoSeed));
    }

    std::printf("TestI2pKeyBlob ok\n");
    return 0;
}
