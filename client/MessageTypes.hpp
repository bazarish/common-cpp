// Bazarish project (c) 2026
#pragma once

namespace bazarish::client {

inline constexpr char kTypeText[] = "text";
inline constexpr char kTypeImage[] = "image";
inline constexpr char kTypeAudio[] = "audio";
inline constexpr char kTypeFile[] = "file";
inline constexpr char kTypeEdit[] = "edit";
inline constexpr char kTypeDelete[] = "delete";
inline constexpr char kTypeReaction[] = "reaction";
inline constexpr char kTypeReceipt[] = "receipt";
inline constexpr char kTypeChatClear[] = "chat.clear";
inline constexpr char kTypeChatTimer[] = "chat.timer";
inline constexpr char kTypeBotMenu[] = "bot.menu";
inline constexpr char kTypeBotCommand[] = "bot.command";
inline constexpr char kTypeBotCallback[] = "bot.callback";
inline constexpr char kTypeContactRequest[] = "contact.request";
inline constexpr char kTypeContactAccept[] = "contact.accept";
inline constexpr char kTypePresenceSchedule[] = "presence.schedule";
inline constexpr char kTypeAccountEpochs[] = "account.epochs";
inline constexpr char kTypeAccountDevices[] = "account.devices";
inline constexpr char kTypeUnsupported[] = "unsupported";
inline constexpr char kTypeGroupState[] = "group.state";
inline constexpr char kTypeGroupReactions[] = "group.reactions";
inline constexpr char kTypeCallPrefix[] = "call.";

inline constexpr char kTypeDeviceChatClear[] = "device.chat-clear";
inline constexpr char kTypeDeviceAccountName[] = "device.account-name";
inline constexpr char kTypeDeviceAccountPrefs[] = "device.account-prefs";
inline constexpr char kTypeDeviceSavedClear[] = "device.saved-clear";
inline constexpr char kTypeDeviceContactRemove[] = "device.contact-remove";
inline constexpr char kTypeDeviceContactBlock[] = "device.contact-block";
inline constexpr char kTypeDeviceContactPrefs[] = "device.contact-prefs";
inline constexpr char kTypeDeviceContactAccepted[] = "device.contact-accepted";
inline constexpr char kTypeDeviceContact[] = "device.contact";
inline constexpr char kTypeDeviceRead[] = "device.read";
inline constexpr char kTypeDeviceChatPin[] = "device.chat-pin";
inline constexpr char kTypeDeviceEpochs[] = "device.epochs";
inline constexpr char kTypeDeviceDevices[] = "device.devices";

inline constexpr char kGroupKindGroup[] = "group";
inline constexpr char kGroupKindChannel[] = "channel";

// A row this device writes itself; it never travels.
inline constexpr char kTypeSystem[] = "system";

}  // namespace bazarish::client
