#!/usr/bin/env swift

// Muxes a narration track onto a screen recording using AVFoundation.
//
// This exists because the machine has no ffmpeg, and installing one just to
// attach an audio track is a heavier dependency than the task needs. macOS
// ships everything required: `say` renders the voiceover, and AVFoundation
// composes it onto the video.
//
//   swift narrate_video.swift <video> <audio> <output.mov>
//
// The audio is placed at the start and truncated to the video's duration if it
// runs long, so a narration overrun cannot extend the clip past its last frame.

import AVFoundation
import Foundation

let args = CommandLine.arguments
guard args.count == 4 else {
    FileHandle.standardError.write("usage: narrate_video.swift <video> <audio> <output.mov>\n".data(using: .utf8)!)
    exit(2)
}

let videoURL = URL(fileURLWithPath: args[1])
let audioURL = URL(fileURLWithPath: args[2])
let outputURL = URL(fileURLWithPath: args[3])

if FileManager.default.fileExists(atPath: outputURL.path) {
    try? FileManager.default.removeItem(at: outputURL)
}

let semaphore = DispatchSemaphore(value: 0)
var failure: String?

Task {
    defer { semaphore.signal() }
    do {
        let videoAsset = AVURLAsset(url: videoURL)
        let audioAsset = AVURLAsset(url: audioURL)
        let composition = AVMutableComposition()

        let videoDuration = try await videoAsset.load(.duration)
        let videoRange = CMTimeRange(start: .zero, duration: videoDuration)

        guard let sourceVideo = try await videoAsset.loadTracks(withMediaType: .video).first,
              let compositionVideo = composition.addMutableTrack(
                  withMediaType: .video, preferredTrackID: kCMPersistentTrackID_Invalid) else {
            failure = "no video track in \(videoURL.lastPathComponent)"
            return
        }
        try compositionVideo.insertTimeRange(videoRange, of: sourceVideo, at: .zero)
        // Preserve orientation/scale; a screen recording carries a transform.
        compositionVideo.preferredTransform = try await sourceVideo.load(.preferredTransform)

        guard let sourceAudio = try await audioAsset.loadTracks(withMediaType: .audio).first,
              let compositionAudio = composition.addMutableTrack(
                  withMediaType: .audio, preferredTrackID: kCMPersistentTrackID_Invalid) else {
            failure = "no audio track in \(audioURL.lastPathComponent)"
            return
        }
        let audioDuration = try await audioAsset.load(.duration)
        let narrationRange = CMTimeRange(
            start: .zero,
            duration: CMTimeMinimum(audioDuration, videoDuration))
        try compositionAudio.insertTimeRange(narrationRange, of: sourceAudio, at: .zero)

        guard let export = AVAssetExportSession(
            asset: composition, presetName: AVAssetExportPresetHighestQuality) else {
            failure = "could not create export session"
            return
        }
        export.outputURL = outputURL
        export.outputFileType = .mov
        try await export.export(to: outputURL, as: .mov)

        if audioDuration > videoDuration {
            let over = CMTimeGetSeconds(audioDuration) - CMTimeGetSeconds(videoDuration)
            FileHandle.standardError.write(
                "warning: narration ran \(String(format: "%.1f", over))s past the video and was truncated\n"
                    .data(using: .utf8)!)
        }
        print("wrote \(outputURL.path) · video \(String(format: "%.1f", CMTimeGetSeconds(videoDuration)))s · narration \(String(format: "%.1f", CMTimeGetSeconds(audioDuration)))s")
    } catch {
        failure = "\(error)"
    }
}

semaphore.wait()
if let failure {
    FileHandle.standardError.write("error: \(failure)\n".data(using: .utf8)!)
    exit(1)
}
