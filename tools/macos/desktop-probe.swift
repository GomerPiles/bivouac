// Disposable-guest validation only. AppKit/MetalKit exercise real window
// visibility, GPU rendering and the application event path without host privileges or TCC
// changes. These are app-routed events, not a host-to-guest hardware-input test.
import AppKit
import Foundation
import MetalKit

private func require(_ value: Bool, _ stage: Int = #line) {
    if !value {
        FileHandle.standardOutput.write(Data(("{\"failed_stage\":" + String(stage) + "}\n").utf8))
        exit(1)
    }
}

private func pump(until predicate: () -> Bool, seconds: TimeInterval = 5, stage: Int = #line) {
    let deadline = Date().addingTimeInterval(seconds)
    while !predicate() && Date() < deadline {
        if let event = NSApp.nextEvent(matching: .any, until: Date().addingTimeInterval(0.01), inMode: .default, dequeue: true) {
            NSApp.sendEvent(event)
        }
        NSApp.updateWindows()
        CATransaction.flush()
        _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.01))
    }
    require(predicate(), stage)
}

private final class DrawProbe: NSObject, MTKViewDelegate {
    let device: MTLDevice
    let queue: MTLCommandQueue
    var drawable: CAMetalDrawable?
    var verified = false

    init(device: MTLDevice) {
        self.device = device
        guard let queue = device.makeCommandQueue() else { exit(1) }
        self.queue = queue
    }

    func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {}

    func draw(in view: MTKView) {
        guard let drawable = view.currentDrawable,
              let command = queue.makeCommandBuffer(),
              let readback = device.makeBuffer(length: 256, options: .storageModeShared) else { return }
        let pass = MTLRenderPassDescriptor()
        pass.colorAttachments[0].texture = drawable.texture
        pass.colorAttachments[0].loadAction = .clear
        pass.colorAttachments[0].storeAction = .store
        pass.colorAttachments[0].clearColor = MTLClearColor(red: 0.2, green: 0.4, blue: 0.6, alpha: 1)
        guard let render = command.makeRenderCommandEncoder(descriptor: pass) else { return }
        render.endEncoding()
        guard let blit = command.makeBlitCommandEncoder() else { return }
        blit.copy(from: drawable.texture, sourceSlice: 0, sourceLevel: 0,
                  sourceOrigin: MTLOrigin(x: 0, y: 0, z: 0), sourceSize: MTLSize(width: 1, height: 1, depth: 1),
                  to: readback, destinationOffset: 0, destinationBytesPerRow: 256, destinationBytesPerImage: 256)
        blit.endEncoding()
        command.present(drawable)
        command.commit()
        command.waitUntilCompleted()
        guard command.status == .completed else { return }
        let pixels = readback.contents().bindMemory(to: UInt8.self, capacity: 4)
        let expected = [153, 102, 51, 255]
        require((0..<4).allSatisfy { abs(Int(pixels[$0]) - expected[$0]) <= 2 })
        self.drawable = drawable
        verified = true
    }
}

private final class ClickProbe: NSObject {
    var clicks = 0
    @objc func click(_ sender: Any?) { clicks += 1 }
}

@main
private struct DesktopProbe {
    static func main() {
        // Refuse to open windows accidentally on the physical host.
        let address = Process()
        address.executableURL = URL(fileURLWithPath: "/usr/sbin/ipconfig")
        address.arguments = ["getifaddr", "en0"]
        let pipe = Pipe()
        address.standardOutput = pipe
        address.standardError = FileHandle.nullDevice
        do { try address.run() } catch { exit(1) }
        address.waitUntilExit()
        let lease = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
        require(address.terminationStatus == 0 && lease == "192.0.2.2")

        let app = NSApplication.shared
        require(app.setActivationPolicy(.regular))
        app.finishLaunching()
        require(!NSScreen.screens.isEmpty)
        guard let device = MTLCreateSystemDefaultDevice() else { exit(1) }
        let first = NSWindow(contentRect: NSRect(x: 120, y: 120, width: 480, height: 320),
                             styleMask: [.titled, .closable], backing: .buffered, defer: false)
        let second = NSWindow(contentRect: NSRect(x: 620, y: 120, width: 200, height: 160),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        first.isReleasedWhenClosed = false
        second.isReleasedWhenClosed = false
        first.title = "Bivouac desktop validation"
        second.title = "Bivouac focus validation"
        defer { first.close(); second.close() }
        let field = NSTextField(frame: NSRect(x: 20, y: 240, width: 240, height: 28))
        let button = NSButton(frame: NSRect(x: 280, y: 20, width: 120, height: 32))
        let clicks = ClickProbe()
        button.title = "Validate"
        button.bezelStyle = .rounded
        button.target = clicks
        button.action = #selector(ClickProbe.click(_:))
        first.contentView?.addSubview(field)
        first.contentView?.addSubview(button)
        let view = MTKView(frame: NSRect(x: 20, y: 60, width: 128, height: 128), device: device)
        view.colorPixelFormat = .bgra8Unorm
        view.framebufferOnly = false
        view.isPaused = true
        view.enableSetNeedsDisplay = false
        let draw = DrawProbe(device: device)
        view.delegate = draw
        first.contentView?.addSubview(view)
        first.makeKeyAndOrderFront(nil)
        app.activate(ignoringOtherApps: true)
        pump(until: { first.isKeyWindow && first.isVisible && app.isActive })
        require(NSWorkspace.shared.frontmostApplication?.processIdentifier == ProcessInfo.processInfo.processIdentifier)
        pump(until: { if !draw.verified { view.draw() }; return draw.verified }, stage: 1230)
        // The virtual display may not expose presentation timestamps. Report that
        // separately: window visibility and GPU pixel readback have their own proofs.
        pump(until: { first.occlusionState.contains(.visible) })
        second.makeKeyAndOrderFront(nil)
        pump(until: { second.isKeyWindow })
        first.makeKeyAndOrderFront(nil)
        pump(until: { first.isKeyWindow })
        require(first.makeFirstResponder(field))
        let keys: [(String, UInt16)] = [("b", 11), ("i", 34), ("v", 9), ("o", 31), ("u", 32), ("a", 0), ("c", 8)]
        for (character, code) in keys {
            for type in [NSEvent.EventType.keyDown, .keyUp] {
                guard let event = NSEvent.keyEvent(with: type, location: .zero, modifierFlags: [],
                    timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: first.windowNumber,
                    context: nil, characters: character, charactersIgnoringModifiers: character,
                    isARepeat: false, keyCode: code) else { exit(1) }
                app.postEvent(event, atStart: false)
            }
        }
        pump(until: { (field.currentEditor() as? NSTextView)?.string == "bivouac" })
        require(first.makeFirstResponder(nil))
        require(field.stringValue == "bivouac")
        for type in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
            guard let event = NSEvent.mouseEvent(with: type, location: NSPoint(x: 340, y: 36), modifierFlags: [],
                timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: first.windowNumber,
                context: nil, eventNumber: 1, clickCount: 1, pressure: type == .leftMouseDown ? 1 : 0) else { exit(1) }
            app.postEvent(event, atStart: false)
        }
        pump(until: { clicks.clicks == 1 })
        let result: [String: Any] = ["window_visible": true, "metal_readback": true,
                                  "presentation_timestamp_available": (draw.drawable?.presentedTime ?? 0) > 0,
                                  "focus_verified": true, "typed_characters": 7, "button_actions": 1]
        guard let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]) else { exit(1) }
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
}
