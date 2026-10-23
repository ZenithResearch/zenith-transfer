import Combine
import Foundation

public enum DictationPhase: Equatable, Sendable {
  case idle, authorizing, recording, finishing
}

public enum DictationError: Error, LocalizedError, Equatable, Sendable {
  case microphonePermission, speechPermission, unsupportedLanguage, unavailable, interrupted, tooLong
  public var errorDescription: String? {
    switch self {
    case .microphonePermission:
      return "Allow microphone access in Settings → Zenith to dictate a message. You can still type."
    case .speechPermission:
      return "Allow speech recognition in Settings → Zenith to dictate a message. You can still type."
    case .unsupportedLanguage:
      return "On-device dictation isn’t available for this language on this iPhone. You can still type."
    case .unavailable:
      return "Dictation couldn’t start or finish. Review any text already captured, or try again."
    case .interrupted:
      return "Dictation stopped because the audio connection changed. Review your text before sending."
    case .tooLong:
      return "Dictation reached the message limit. Review your text before sending."
    }
  }
}

public enum DictationEvent: Sendable {
  case transcription(String, isFinal: Bool)
  case failed(DictationError)
}

public protocol DictationDriver: Sendable {
  func authorize() async throws
  func start(receive: @escaping @Sendable (DictationEvent) -> Void) async throws
  func finishAudio() async
  func cancel() async
}

/// A transient composer draft. This type has no network, storage or send callback.
/// Driver operations are serialized; cancelled authorization cannot start capture.
@MainActor
public final class ChatDictation: ObservableObject {
  @Published public var draft = ""
  @Published public private(set) var phase: DictationPhase = .idle
  @Published public private(set) var error: String?
  public var busy: Bool { phase != .idle }
  private let driver: any DictationDriver
  private var operation: Task<Void, Never>?
  private var timer: Task<Void, Never>?
  private var generation = 0
  private var prefix = ""
  var recordingLimitNanoseconds: UInt64 = 55_000_000_000
  var finalizationLimitNanoseconds: UInt64 = 3_000_000_000

  public init(driver: any DictationDriver) { self.driver = driver }

  public func start() {
    guard !busy else { return }
    generation += 1
    let ticket = generation
    prefix = draft
    error = nil
    phase = .authorizing
    let previous = operation
    operation = Task { [weak self, driver] in
      await previous?.value
      do {
        try Task.checkCancellation()
        try await driver.authorize()
        try Task.checkCancellation()
        guard self?.generation == ticket else { return }
        try await driver.start { [weak self] event in
          Task { @MainActor [weak self] in self?.accept(event, ticket: ticket) }
        }
        guard let self, self.generation == ticket, !Task.isCancelled else { return }
        self.phase = .recording
        self.timer = Task { [weak self] in
          do {
            try await Task.sleep(nanoseconds: self?.recordingLimitNanoseconds ?? 0)
            guard self?.generation == ticket else { return }
            self?.stop()
          } catch {}
        }
      } catch {
        guard let self, self.generation == ticket, !Task.isCancelled else { return }
        self.complete(error: (error as? DictationError) ?? .unavailable)
      }
    }
  }

  /// Stop the microphone now, then allow a short bounded final transcription.
  public func stop() {
    guard phase == .recording else { return }
    phase = .finishing
    timer?.cancel()
    let previous = operation
    let ticket = generation
    operation = Task { [weak self, driver] in
      await previous?.value
      guard self?.generation == ticket, !Task.isCancelled else { return }
      await driver.finishAudio()
      guard let self, self.generation == ticket, !Task.isCancelled else { return }
      self.timer = Task { [weak self] in
        do {
          try await Task.sleep(nanoseconds: self?.finalizationLimitNanoseconds ?? 0)
          guard self?.generation == ticket else { return }
          self?.complete()
        } catch {}
      }
    }
  }

  public func discard() {
    guard busy else { return }
    draft = prefix
    complete()
  }

  /// Locking, leaving Chat and changing connections discard the entire draft.
  public func clear() {
    draft = ""
    prefix = ""
    error = nil
    complete()
  }

  private func accept(_ event: DictationEvent, ticket: Int) {
    guard generation == ticket, busy else { return }
    switch event {
    case .transcription(let text, let final):
      let transcript = String(text.prefix(8192)).trimmingCharacters(in: .whitespacesAndNewlines)
      draft = prefix + (prefix.isEmpty || transcript.isEmpty || prefix.last?.isWhitespace == true ? "" : " ") + transcript
      if text.count > 8192 { complete(error: .tooLong) }
      else if final { complete() }
    case .failed(let error): complete(error: error)
    }
  }

  private func complete(error: DictationError? = nil) {
    generation += 1
    let ticket = generation
    timer?.cancel()
    timer = nil
    self.error = error?.localizedDescription
    let previous = operation
    previous?.cancel()
    phase = .finishing
    operation = Task { [weak self, driver] in
      await previous?.value
      await driver.cancel()
      guard let self, self.generation == ticket else { return }
      self.phase = .idle
    }
  }
}
