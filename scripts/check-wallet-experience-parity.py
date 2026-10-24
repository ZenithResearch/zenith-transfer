"""Fail when the two native applications drift in shared Wallet UI or policy."""
import hashlib
import json
from pathlib import Path
import sys

local = Path(__file__).resolve().parents[1]
if len(sys.argv) != 2:
    raise SystemExit('Usage: python3 scripts/check-wallet-experience-parity.py /path/to/other-native-app')
other = Path(sys.argv[1])
paths = [
    'Sources/ZenithKit/HolderGrants.swift',
    'Sources/ZenithKit/WalletGrantsView.swift',
    'Sources/ZenithKit/DevgraphReadClient.swift',
    'Tests/ZenithKitTests/ReadContractTests.swift',
    'Sources/CastaliaCustody/LifecycleGate.swift',
    'Sources/CastaliaCustody/NativeSignerEngine.swift',
    'Sources/CastaliaCustody/WalletRepository.swift',
    'Sources/CastaliaSignerProtocol/SignerServiceChallenge.swift',
    'Sources/ZenithKit/WalletFailure.swift',
    'Sources/ZenithKit/WalletSession.swift',
    'Tests/ZenithKitTests/NativeSignerEngineTests.swift',
    'Sources/CastaliaSignerProtocol/SignerClientSession.swift',
    'Sources/CastaliaSignerProtocol/SignerConsentJournal.swift',
    'Sources/CastaliaSignerProtocol/SignerHandoffURL.swift',
    'Sources/CastaliaSignerProtocol/SignerHostCoordinator.swift',
    'Sources/CastaliaSignerProtocol/SignerMessages.swift',
    'Sources/CastaliaSignerProtocol/SignerSealedHandoff.swift',
    'Sources/CastaliaSignerProtocol/StrictSignerJSON.swift',
    'Sources/CastaliaSignerStorage/EncryptedSignerJournal.swift',
    'Sources/CastaliaSignerStorage/SignerDeviceVault.swift',
    'Sources/CastaliaSignerTransport/SignerXPC.swift',
    'Tests/ZenithKitTests/SignerHostCoordinatorTests.swift',
    'Tests/ZenithKitTests/SignerProtocolTests.swift',
    'Tests/ZenithKitTests/SignerStorageAndHandoffTests.swift',
    'Sources/ZenithKit/WalletExperience.swift',
    'Sources/ZenithKit/WalletComponents.swift',
    'Sources/ZenithKit/WalletActivityTracking.swift',
    'Sources/ZenithKit/IdentityAccount.swift',
    'Sources/ZenithKit/WalletIdentity.swift',
    'Sources/ZenithKit/PortableSummary.swift',
    'Sources/CastaliaCustody/SnapshotStore.swift',
    'Sources/ZenithKit/WalletIdentitiesView.swift',
    'Sources/ZenithKit/EncryptedImportFile.swift',
    'Sources/ZenithKit/RecoveryFileCatalog.swift',
    'Tests/ZenithKitTests/WalletExperienceTests.swift',
    'Tests/ZenithKitTests/IdentityAccountTests.swift',
    'Tests/ZenithKitTests/WalletIdentityTests.swift',
    'Tests/ZenithKitTests/PortableWalletIdentityIntegrationTests.swift',
    'Tests/ZenithKitTests/Fixtures/wallet-identities-v1.json',
]
for path in paths:
    if (local / path).read_bytes() != (other / path).read_bytes():
        raise SystemExit('Native Wallet source differs: ' + path)
pins = [json.loads((root / 'Dependencies.json').read_text())['wallet'] for root in (local, other)]
if pins[0] != pins[1]:
    raise SystemExit('Native Wallet dependency pins differ')
print(json.dumps({'shared_files': len(paths), 'wallet_revision': pins[0]['revision'], 'parity': True}))
