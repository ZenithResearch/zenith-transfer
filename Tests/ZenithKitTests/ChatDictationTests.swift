import XCTest
@testable import ZenithKit

private actor FakeDictationDriver: DictationDriver {
  private(set) var starts = 0
  private(set) var finishes = 0
  private(set) var cancels = 0
  private var callbacks: [@Sendable (DictationEvent) -> Void] = []
  private var gate: CheckedContinuation<Void, Never>?
  private var holdAuthorization = false
  private var failure: DictationError?
  func pauseAuthorization() { holdAuthorization = true }
  func failAuthorization(_ error: DictationError) { failure = error }
  var authorizationPending: Bool { gate != nil }
  func releaseAuthorization() { let previous = gate; gate = nil; previous?.resume() }
  func authorize() async throws {
    if holdAuthorization {
      holdAuthorization = false
      await withCheckedContinuation { gate = $0 }
    }
    if let failure { throw failure }
  }
  func start(receive: @escaping @Sendable (DictationEvent) -> Void) async throws {
    starts += 1
    callbacks.append(receive)
  }
  func finishAudio() async { finishes += 1 }
  func cancel() async { cancels += 1 }
  func emit(_ event: DictationEvent, session: Int = 0) { callbacks[session](event) }
}

final class ChatDictationTests: XCTestCase {
  @MainActor
  func testFinalTranscriptReplacesPartialAndPreservesTypedDraft() async {
    let driver = FakeDictationDriver()
    let voice = ChatDictation(driver: driver)
    voice.draft = "Please check"
    voice.start()
    await eventually { voice.phase == .recording }
    await driver.emit(.transcription("my gate", isFinal: false))
    await eventually { voice.draft == "Please check my gate" }
    voice.stop()
    await eventually { await driver.finishes == 1 }
    XCTAssertTrue(voice.busy)
    await driver.emit(.transcription("my gateway.", isFinal: true))
    await eventually { voice.phase == .idle }
    XCTAssertEqual(voice.draft, "Please check my gateway.")
    voice.draft = "Reviewed text"
    await driver.emit(.transcription("late result", isFinal: true))
    await Task.yield()
    XCTAssertEqual(voice.draft, "Reviewed text")
  }

  @MainActor
  func testDiscardRestoresOriginalAndRejectsCallbacksFromOlderRecording() async {
    let driver = FakeDictationDriver()
    let voice = ChatDictation(driver: driver)
    voice.draft = "Keep this. "
    voice.start()
    await eventually { voice.phase == .recording }
    await driver.emit(.transcription("Discard this", isFinal: false))
    await eventually { voice.draft == "Keep this. Discard this" }
    voice.discard()
    await eventually { !voice.busy }
    XCTAssertEqual(voice.draft, "Keep this. ")
    voice.start()
    await eventually { await driver.starts == 2 }
    await driver.emit(.transcription("stale dictation", isFinal: true))
    await driver.emit(.transcription("New text", isFinal: true), session: 1)
    await eventually { !voice.busy }
    XCTAssertEqual(voice.draft, "Keep this. New text")
  }

  @MainActor
  func testClearingDuringPermissionPromptCannotStartMicrophoneLater() async {
    let driver = FakeDictationDriver()
    await driver.pauseAuthorization()
    let voice = ChatDictation(driver: driver)
    voice.draft = "Private draft"
    voice.start()
    await eventually { await driver.authorizationPending }
    voice.clear()
    await driver.releaseAuthorization()
    await eventually { !voice.busy }
    let starts = await driver.starts
    XCTAssertEqual(starts, 0)
    XCTAssertEqual(voice.draft, "")
  }

  @MainActor
  func testPermissionDenialKeepsTypingAvailableAndRedactsErrors() async {
    let driver = FakeDictationDriver()
    await driver.failAuthorization(.microphonePermission)
    let voice = ChatDictation(driver: driver)
    voice.draft = "Typed message"
    voice.start()
    await eventually { !voice.busy }
    XCTAssertEqual(voice.draft, "Typed message")
    XCTAssertEqual(voice.error, DictationError.microphonePermission.localizedDescription)
    let starts = await driver.starts
    XCTAssertEqual(starts, 0)
  }

  @MainActor
  func testRecordingAndFinalizationHaveBoundsAndLateTextCannotReappearAfterLock() async {
    let driver = FakeDictationDriver()
    let voice = ChatDictation(driver: driver)
    voice.recordingLimitNanoseconds = 100_000_000
    voice.finalizationLimitNanoseconds = 20_000_000
    voice.start()
    await eventually { voice.phase == .recording }
    await driver.emit(.transcription("Captured text", isFinal: false))
    await eventually { !voice.busy }
    XCTAssertEqual(voice.draft, "Captured text")
    let finishes = await driver.finishes
    XCTAssertEqual(finishes, 1)
    voice.clear()
    await driver.emit(.transcription("Private late result", isFinal: true))
    await eventually { !voice.busy }
    XCTAssertEqual(voice.draft, "")
    XCTAssertNil(voice.error)
  }

  @MainActor
  func testInterruptionKeepsCapturedTextForReviewAndClosesCapture() async {
    let driver = FakeDictationDriver()
    let voice = ChatDictation(driver: driver)
    voice.start()
    await eventually { voice.phase == .recording }
    await driver.emit(.transcription("Please check the gateway", isFinal: false))
    await eventually { !voice.draft.isEmpty }
    await driver.emit(.failed(.interrupted))
    await eventually { !voice.busy }
    XCTAssertEqual(voice.draft, "Please check the gateway")
    XCTAssertEqual(voice.error, DictationError.interrupted.localizedDescription)
    let cancels = await driver.cancels
    XCTAssertGreaterThanOrEqual(cancels, 1)
  }

  @MainActor
  private func eventually(_ predicate: @escaping @MainActor () async -> Bool,
    file: StaticString = #filePath, line: UInt = #line) async {
    for _ in 0..<300 {
      if await predicate() { return }
      try? await Task.sleep(nanoseconds: 5_000_000)
    }
    XCTFail("Timed out waiting for dictation lifecycle", file: file, line: line)
  }
}
