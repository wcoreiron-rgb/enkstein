#!/usr/bin/env swift

// Assembles per-beat narration clips into one audio track, each placed at its
// scripted offset.
//
// `say` renders one clip per beat, but the demo script gives each beat a start
// timecode. Concatenating the clips would drift out of sync with the visuals
// after the first beat that reads short, so placement has to be absolute.
//
//   swift assemble_narration.swift <output.m4a> <offsetSeconds> <clip.aiff> [...]
//
// Silence between beats is implicit: an AVMutableComposition track has no
// samples where nothing was inserted.

import AVFoundation
import Foundation

let args = Array(CommandLine.arguments.dropFirst())
guard args.count >= 3, (args.count - 1) % 2 == 0 else {
    FileHandle.standardError.write(
        "usage: assemble_narration.swift <output.m4a> <offsetSeconds> <clip.aiff> [...]\n"
            .data(using: .utf8)!)
    exit(2)
}

let outputURL = URL(fileURLWithPath: args[0])
var beats: [(offset: Double, url: URL)] = []
var index = 1
while index < args.count {
    guard let offset = Double(args[index]) else {
        FileHandle.standardError.write("error: '\(args[index])' is not a number of seconds\n".data(using: .utf8)!)
        exit(2)
    }
    beats.append((offset, URL(fileURLWithPath: args[index + 1])))
    index += 2
}

if FileManager.default.fileExists(atPath: outputURL.path) {
    try? FileManager.default.removeItem(at: outputURL)
}

let timescale: CMTimeScale = 600
let semaphore = DispatchSemaphore(value: 0)
var failure: String?

Task {
    defer { semaphore.signal() }
    do {
        let composition = AVMutableComposition()
        guard let track = composition.addMutableTrack(
            withMediaType: .audio, preferredTrackID: kCMPersistentTrackID_Invalid) else {
            failure = "could not create an audio track"
            return
        }

        var previousEnd = 0.0
        var previousLabel = ""
        for beat in beats {
            let asset = AVURLAsset(url: beat.url)
            guard let source = try await asset.loadTracks(withMediaType: .audio).first else {
                failure = "no audio track in \(beat.url.lastPathComponent)"
                return
            }
            let duration = try await asset.load(.duration)
            let at = CMTime(seconds: beat.offset, preferredTimescale: timescale)
            try track.insertTimeRange(
                CMTimeRange(start: .zero, duration: duration), of: source, at: at)

            let label = beat.url.deletingPathExtension().lastPathComponent
            if beat.offset < previousEnd {
                let overlap = previousEnd - beat.offset
                FileHandle.standardError.write(
                    "warning: \(label) starts \(String(format: "%.1f", overlap))s before \(previousLabel) finishes\n"
                        .data(using: .utf8)!)
            }
            previousEnd = beat.offset + CMTimeGetSeconds(duration)
            previousLabel = label
            print(String(format: "  %6.1fs  %5.1fs  %@", beat.offset, CMTimeGetSeconds(duration), label))
        }

        guard let export = AVAssetExportSession(
            asset: composition, presetName: AVAssetExportPresetAppleM4A) else {
            failure = "could not create export session"
            return
        }
        try await export.export(to: outputURL, as: .m4a)
        print("wrote \(outputURL.path) · \(String(format: "%.1f", previousEnd))s of narration")
    } catch {
        failure = "\(error)"
    }
}

semaphore.wait()
if let failure {
    FileHandle.standardError.write("error: \(failure)\n".data(using: .utf8)!)
    exit(1)
}
