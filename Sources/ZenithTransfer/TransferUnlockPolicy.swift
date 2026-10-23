#if os(macOS)
import Foundation

enum TransferUnlockDuration:Int,CaseIterable,Identifiable {
  case twoMinutes=120, fiveMinutes=300, fifteenMinutes=900, thirtyMinutes=1800
  case oneHour=3600, fourHours=14400, untilLocked=0
  static let settingKey="Transfer.wallet.unlockDurationSeconds.v1"
  var id:Int { rawValue }
  var label:String {
    switch self {
    case .twoMinutes:return "2 minutes"
    case .fiveMinutes:return "5 minutes"
    case .fifteenMinutes:return "15 minutes"
    case .thirtyMinutes:return "30 minutes"
    case .oneHour:return "1 hour"
    case .fourHours:return "4 hours"
    case .untilLocked:return "Until I lock or quit"
    }
  }
  static func load(_ defaults:UserDefaults)->Self {
    guard let value=defaults.object(forKey:settingKey) as? Int,let duration=Self(rawValue:value) else { return .oneHour }
    return duration
  }
}

/// A fixed period from unlock, not refreshed by reads or background probes.
/// Wall time includes sleep; monotonic elapsed time prevents clock rollback
/// from extending the unlocked interval. No password/key is persisted here.
struct TransferUnlockTimer {
  private(set) var started:Date?
  private var uptime:TimeInterval?
  mutating func observe(unlocked:Bool,now:Date,uptime:TimeInterval) {
    if !unlocked { clear() }
    else if started == nil { started=now;self.uptime=uptime }
  }
  mutating func clear() { started=nil;uptime=nil }
  func expired(_ policy:TransferUnlockDuration,now:Date,uptime:TimeInterval)->Bool {
    guard policy != .untilLocked,let started,let initial=self.uptime else { return false }
    return max(now.timeIntervalSince(started),uptime-initial) >= Double(policy.rawValue)
  }
  func deadline(_ policy:TransferUnlockDuration)->Date? {
    guard policy != .untilLocked else { return nil }
    return started?.addingTimeInterval(Double(policy.rawValue))
  }
}
#endif
