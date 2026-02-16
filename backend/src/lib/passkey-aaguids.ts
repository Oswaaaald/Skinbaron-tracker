/**
 * Well-known AAGUID → authenticator name mapping.
 * AAGUIDs from the FIDO Alliance Metadata Service and community sources.
 * @see https://github.com/passkeydeveloper/passkey-authenticator-aaguids
 */
export const AAGUID_NAMES: Record<string, string> = {
  // ==================== Platform Authenticators ====================
  // Apple
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain',
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain (managed)',
  // Google
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
  'b5397571-f314-4a3f-b949-0f0ce53875f3': 'Google Password Manager (Chromium)',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac',
  // Microsoft
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  '6e96969e-a5cf-4aad-9b56-305fe6c82795': 'Windows Hello',

  // ==================== Password Managers ====================
  // 1Password
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'd548826e-79b4-db40-a3d8-11116f7e8349': '1Password',
  // Bitwarden
  'eacb514b-960a-4a2d-b551-11a57ff39864': 'Bitwarden',
  // Dashlane
  '531126d6-e717-415c-9320-3d9aa6981239': 'Dashlane',
  // KeePassXC
  'b84e4048-15dc-4dd0-8640-f4f60813c8af': 'KeePassXC',
  // NordPass
  '0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6': 'NordPass',
  // Proton Pass
  'bbb8968a-deeb-4c50-a0e5-3f5497272dc5': 'Proton Pass',
  // Enpass
  'f3809540-7f14-49c1-a8b3-8f813b225541': 'Enpass',
  // Samsung Pass
  '53414d53-554e-4700-0000-000000000000': 'Samsung Pass',
  '0acf3011-bc60-f375-fb53-6f05f43154e0': 'Samsung Pass',

  // ==================== YubiKey ====================
  'cb69481e-8ff7-4039-93ec-0a2729a154a8': 'YubiKey 5 (NFC)',
  'ee882879-721c-4913-9775-3dfcce97072a': 'YubiKey 5 (Nano)',
  'fa2b99dc-9e39-4257-8f92-4a30d23c4118': 'YubiKey 5 (NFC FIPS)',
  '73bb0cd4-e502-49b8-9c6f-b59445bf720b': 'YubiKey 5 (FIPS)',
  'c5ef55ff-ad9a-4b9f-b580-adebafe026d0': 'YubiKey 5Ci (FIPS)',
  '85203421-48f9-4355-9bc8-8a53846e5083': 'YubiKey 5Ci',
  '2fc0579f-8113-47ea-b116-bb5a8db9202a': 'YubiKey 5 (NFC)',
  'a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa': 'Security Key (NFC)',
  'd8522d9f-575b-4866-88a9-ba99fa02f35b': 'YubiKey Bio',
  'f8a011f3-8c0a-4d15-8006-17111f9edc7d': 'Security Key',
  'b92c3f9a-c014-4056-887f-140a2501163b': 'Security Key (NFC)',
  'e77e3c64-05e3-428c-8824-0cbeb04b829d': 'YubiKey 5 (USB-C)',

  // ==================== Other Hardware Keys ====================
  // Feitian
  '12ded745-4bed-47d4-abaa-e713f51d6393': 'Feitian BioPass',
  '77010bd7-212a-4fc9-b236-d2ca5e9d4084': 'Feitian iePASS',
  // SoloKeys
  '8876631b-d4a0-427f-5773-0ec71c9e0279': 'SoloKey',
  // Nitrokey
  '2c0df832-92de-4be1-8412-88a8f074df4a': 'Nitrokey 3',
  // Google Titan
  '42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3': 'Google Titan',
};

/**
 * Resolve a friendly authenticator name from an AAGUID.
 * Returns the mapped name, or a generic fallback based on device type / transports.
 */
export function resolvePasskeyName(
  aaguid: string,
  deviceType?: string,
  transports?: string[],
): string {
  // Try exact AAGUID match
  const known = AAGUID_NAMES[aaguid];
  if (known) return known;

  // Skip the zero AAGUID (privacy-preserving, no info)
  if (aaguid === '00000000-0000-0000-0000-000000000000') {
    // Fall through to heuristics
  }

  // Heuristic based on transports
  if (transports?.includes('usb')) return 'Security Key (USB)';
  if (transports?.includes('nfc')) return 'Security Key (NFC)';
  if (transports?.includes('ble')) return 'Security Key (Bluetooth)';

  // Heuristic based on device type
  if (transports?.includes('internal') && transports?.includes('hybrid')) {
    return deviceType === 'multiDevice' ? 'Synced Passkey' : 'Device Passkey';
  }
  if (transports?.includes('internal')) {
    return 'Device Passkey';
  }

  // Default
  return 'Passkey';
}
