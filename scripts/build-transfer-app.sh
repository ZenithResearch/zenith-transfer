#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
swift build --product ZenithTransfer
binary_dir=$(swift build --show-bin-path)
final_app="${TRANSFER_APP_OUTPUT:-$project_dir/Artifacts/Zenith Transfer.app}"
stage_dir=$(mktemp -d "$project_dir/Artifacts/transfer-build.XXXXXX")
app_dir="$stage_dir/Zenith Transfer.app"
mkdir -p "$app_dir/Contents/MacOS"
mkdir -p "$app_dir/Contents/Resources"
cp "$binary_dir/ZenithTransfer" "$app_dir/Contents/MacOS/ZenithTransfer"
cp -R "$binary_dir/ZenithKit_ZenithTransfer.bundle" "$app_dir/Contents/Resources/ZenithKit_ZenithTransfer.bundle"
# Reuse Zenith's established artwork, including the macOS app icon.
icon_dir=$(mktemp -d "${TMPDIR:-/tmp}/zenith-transfer-icon.XXXXXX")
trap 'rm -rf "$icon_dir" "$stage_dir"' EXIT
mkdir "$icon_dir/Zenith.iconset"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$project_dir/Artwork/AppIcon.png" --out "$icon_dir/Zenith.iconset/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  sips -z "$double" "$double" "$project_dir/Artwork/AppIcon.png" --out "$icon_dir/Zenith.iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$icon_dir/Zenith.iconset" -o "$app_dir/Contents/Resources/Zenith.icns"
cat > "$app_dir/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>ZenithTransfer</string>
<key>CFBundleIdentifier</key><string>ca.zenith.preview.transfer</string>
<key>CFBundleName</key><string>Zenith Transfer</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.2.0</string>
<key>CFBundleVersion</key><string>48</string>
<key>CFBundleIconFile</key><string>Zenith</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign --force --sign - "$app_dir"
codesign --verify --strict "$app_dir"
# Never overwrite an executable mapped by a running version of the app.
if [ -d "$final_app" ]; then
  previous_dir=$(mktemp -d "$project_dir/Artifacts/transfer-previous.XXXXXX")
  mv "$final_app" "$previous_dir/Zenith Transfer.app"
fi
mv "$app_dir" "$final_app"
python3 "$project_dir/scripts/prune-build-backups.py" --apply
printf 'Built %s\n' "$final_app"
