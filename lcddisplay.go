// Package main provides a tool for rendering HTML content and system information to an AX206-based LCD display via USB.
//
// This application uses the chromedp library to render HTML pages or URLs into screenshots,
// which are then converted to the appropriate pixel format and transmitted to an AX206 LCD device
// through USB bulk transfers using the SCSI-over-USB protocol.
//
// Features:
//   - Render local HTML files or remote URLs to the LCD display
//   - Support for multiple pixel formats (RGB565, BGR565, BRG565)
//   - Configurable endianness (big/little)
//   - Image rotation (0°, 90°, 180°, 270°)
//   - Loop mode with configurable intervals
//   - Built-in HTTP server providing real-time system information endpoints
//   - Verbose logging for debugging
//
// The system information server exposes various endpoints at http://localhost:8080/system/*
// for monitoring memory, CPU, disk, network, temperature, processes, and other system metrics.
//
// USB Protocol:
// The AX206 device communicates using a custom SCSI-over-USB protocol with:
//   - Vendor ID: 0x1908
//   - Product ID: 0x0102
//   - Bulk OUT endpoint: 0x01
//   - Bulk IN endpoint: 0x81
//
// Command-line flags:
//   --html        Path to local HTML file to render
//   --url         External URL to render
//   --loop        Enable continuous rendering in a loop
//   --interval    Time between renders in loop mode (default: 1s)
//   --format      Pixel format: rgb565, bgr565, or brg565 (default: rgb565)
//   --endian      Byte order: little or big (default: big)
//   --verbose     Enable detailed logging output
//   --rotate      Rotation angle in degrees: 0, 90, 180, or 270 (default: 0)
//   --info        Display LCD resolution and exit
//
// Example usage:
//   lcddisplay --html dashboard.html --loop --interval=5s --format=brg565 --rotate=90
//   lcddisplay --url https://example.com --verbose
//   lcddisplay --info

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/google/gousb"
)

// / USB device parameters
const (
	vid      = 0x1908
	pid      = 0x0102
	endptOut = 0x01
	endptIn  = 0x81
)

// / Command-line flags
var (
	htmlFile = flag.String("html", "", "Render a local HTML file")
	urlFlag  = flag.String("url", "", "Render an external URL")
	loop     = flag.Bool("loop", false, "Run in infinite loop")
	info     = flag.Bool("info", false, "Show display information")
	format   = flag.String("format", "rgb565", "Color format: rgb565, bgr565, brg565")
	endian   = flag.String("endian", "big", "Endianness: little or big")
	verbose  = flag.Bool("verbose", false, "Enable verbose logging")
	rotate   = flag.Int("rotate", 0, "Image rotation in degrees (0, 90, 180, 270)")
	chromiumPath = flag.String("chromium", "/usr/bin/chromium", "Path to Chromium/Chrome executable")
	interval = flag.Duration("interval", time.Second, "Interval between renderings in loop mode (e.g., 200ms, 1s)")
)

// / AX206 represents the AX206 LCD device and provides methods for communication.
type ax206 struct {
	dev    *gousb.Device
	cfg    *gousb.Config
	intf   *gousb.Interface
	outEP  *gousb.OutEndpoint
	inEP   *gousb.InEndpoint
	width  int
	height int
}

// / openAX206 initializes and opens a connection to the AX206 LCD device.
// / ctx: Context for USB operations.
// / Returns: *ax206, error
func openAX206(ctx context.Context) (*ax206, error) {
	usbCtx := gousb.NewContext()
	dev, err := usbCtx.OpenDeviceWithVIDPID(vid, pid)
	if err != nil {
		return nil, fmt.Errorf("open device: %w, need proper permissions?", err)
	}
	if dev == nil {
		return nil, fmt.Errorf("device %04x:%04x not found", vid, pid)
	}
	cfg, err := dev.Config(1)
	if err != nil {
		dev.Close()
		return nil, err
	}
	intf, err := cfg.Interface(0, 0)
	if err != nil {
		cfg.Close()
		dev.Close()
		return nil, err
	}
	outEP, err := intf.OutEndpoint(endptOut)
	if err != nil {
		intf.Close()
		cfg.Close()
		dev.Close()
		return nil, err
	}
	inEP, err := intf.InEndpoint(endptIn)
	if err != nil {
		intf.Close()
		cfg.Close()
		dev.Close()
		return nil, err
	}

	ax := &ax206{dev: dev, cfg: cfg, intf: intf, outEP: outEP, inEP: inEP}
	w, h, err := ax.getLCDParams()
	if err != nil {
		return nil, err
	}
	ax.width, ax.height = w, h
	return ax, nil
}

// / Close releases resources associated with the AX206 device.
// / Parameters: none
func (a *ax206) Close() {
	if a.intf != nil {
		a.intf.Close()
	}
	if a.cfg != nil {
		a.cfg.Close()
	}
	if a.dev != nil {
		a.dev.Close()
	}
}

// / getLCDParams retrieves the width and height of the LCD display.
// / Width and height of the LCD display.
// / Returns: int, int, error
func (a *ax206) getLCDParams() (int, int, error) {
	excmd := make([]byte, 16)
	excmd[0] = 0xcd
	excmd[5] = 0x02
	reply := make([]byte, 5)
	if err := a.wrapSCSI(excmd, excmd, false, reply, uint32(len(reply))); err != nil {
		return 0, 0, err
	}
	w := int(binary.LittleEndian.Uint16(reply[0:2]))
	h := int(binary.LittleEndian.Uint16(reply[2:4]))
	return w, h, nil
}

// / wrapSCSI sends a SCSI command wrapped in the AX206 USB protocol.
// / cmd is the SCSI command to send.
// / cmdPayload is the payload associated with the command.
// / dirOut indicates the direction of data transfer (true for OUT, false for IN).
// / data is the buffer for data transfer.
// / blockLen is the length of the data to transfer.
// / Returns: error

func (a *ax206) wrapSCSI(cmd []byte, cmdPayload []byte, dirOut bool, data []byte, blockLen uint32) error {
	cbw := make([]byte, 31+16)
	copy(cbw[0:4], []byte("USBC"))
	copy(cbw[4:8], []byte{0xde, 0xad, 0xbe, 0xef})
	binary.LittleEndian.PutUint32(cbw[8:12], blockLen)
	if dirOut {
		cbw[12] = 0x00
	} else {
		cbw[12] = 0x80
	}
	cbw[13] = 0x00
	cbw[14] = byte(len(cmdPayload))
	copy(cbw[15:31], cmdPayload)
	if _, err := a.outEP.Write(cbw); err != nil {
		return err
	}
	if dirOut {
		if data != nil && blockLen > 0 {
			if _, err := a.outEP.Write(data); err != nil {
				return err
			}
		}
	} else {
		if data != nil && blockLen > 0 {
			if _, err := a.inEP.Read(data); err != nil {
				return err
			}
		}
	}
	ack := make([]byte, 13)
	if _, err := a.inEP.Read(ack); err != nil {
		return err
	}
	if string(ack[0:4]) != "USBS" {
		return fmt.Errorf("bad ACK")
	}
	if ack[12] != 0x00 {
		return fmt.Errorf("status %02x", ack[12])
	}
	return nil
}

// / blit sends image data to the LCD display within specified coordinates.
// / Parameters: img []byte, x0, y0, x1, y1 int, cmd byte
// / Image data to send.
// / x0, y0: Top-left coordinates.
// / x1, y1: Bottom-right coordinates.
// / cmd: Command byte for the blit operation.
// / Returns: error
func (a *ax206) blit(img []byte, x0, y0, x1, y1 int, cmd byte) error {
	excmd := make([]byte, 16)
	excmd[0] = 0xcd
	excmd[5] = cmd
	excmd[7] = byte(x0 & 0xff)
	excmd[8] = byte(x0 >> 8)
	excmd[9] = byte(y0 & 0xff)
	excmd[10] = byte(y0 >> 8)
	excmd[11] = byte((x1 - 1) & 0xff)
	excmd[12] = byte((x1 - 1) >> 8)
	excmd[13] = byte((y1 - 1) & 0xff)
	excmd[14] = byte((y1 - 1) >> 8)
	return a.wrapSCSI(excmd, excmd, true, img, uint32(len(img)))
}

// / convertPixel converts RGB values to a 16-bit pixel format.
// / r Red component (0-255).
// / g Green component (0-255).
// / b Blue component (0-255).
// / format Pixel format: "rgb565", "bgr565", or "brg565".
// / Returns: uint16
func convertPixel(r, g, b uint8, format string) uint16 {
	switch format {
	case "rgb565":
		return (uint16(r)&0xF8)<<8 | (uint16(g)&0xFC)<<3 | (uint16(b)&0xF8)>>3
	case "bgr565":
		return (uint16(b)&0xF8)<<8 | (uint16(g)&0xFC)<<3 | (uint16(r)&0xF8)>>3
	case "brg565":
		return (uint16(b)&0xF8)<<8 | (uint16(r)&0xFC)<<3 | (uint16(g)&0xF8)>>3
	default:
		// fallback para brg565
		return (uint16(b)&0xF8)<<8 | (uint16(r)&0xFC)<<3 | (uint16(g)&0xF8)>>3
	}
}

// / enableConsoleLogging sets up listeners to capture console messages and exceptions from Chromium.
// / ctx: Context for Chromium operations.
func enableConsoleLogging(ctx context.Context) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			for _, arg := range e.Args {
				fmt.Printf("[Chromium console.%s] %s\n", e.Type.String(), arg.Value)
			}
		case *runtime.EventExceptionThrown:
			fmt.Printf("[Chromium exception] %s\n", e.ExceptionDetails.Text)
		}
	})
}

// / rotateImage rotates the given image by the specified angle (90, 180, 270 degrees).
// / img: The image to rotate.
// / angle: Rotation angle in degrees (90, 180, 270).
// / Returns: Rotated image.
func rotateImage(img image.Image, angle int) image.Image {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()

	switch angle {
	case 90:
		dst := image.NewRGBA(image.Rect(0, 0, h, w))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				dst.Set(h-y-1, x, img.At(x, y))
			}
		}
		return dst
	case 180:
		dst := image.NewRGBA(image.Rect(0, 0, w, h))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				dst.Set(w-x-1, h-y-1, img.At(x, y))
			}
		}
		return dst
	case 270:
		dst := image.NewRGBA(image.Rect(0, 0, h, w))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				dst.Set(y, w-x-1, img.At(x, y))
			}
		}
		return dst
	default:
		return img
	}
}

// / convertToBuffer converts an image to a byte buffer in the specified pixel format and endianess.
// / img: The image to convert.
// / w Width of the image.
// / h Height of the image.
// / format Pixel format: "rgb565", "bgr565", or "brg565".
// / endian Endianness: "little" or "big".
// / Returns: Byte buffer containing the converted image data.
func convertToBuffer(img image.Image, w, h int, format, endian string) []byte {
	buf := make([]byte, w*h*2)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			R := uint8(r >> 8)
			G := uint8(g >> 8)
			B := uint8(b >> 8)
			p := convertPixel(R, G, B, format)
			lo := byte(p & 0xff)
			hi := byte(p >> 8)
			off := (y*w + x) * 2
			if endian == "big" {
				buf[off] = hi
				buf[off+1] = lo
			} else {
				buf[off] = lo
				buf[off+1] = hi
			}
		}
	}
	return buf
}

// / withCORS is a middleware that adds CORS headers to HTTP responses.
// / h is the HTTP handler function to wrap.
func withCORS(h http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        if origin != "http://localhost:8080" && origin != "null" {
            http.Error(w, "Forbidden", http.StatusForbidden)
            log.Printf("Blocked request from origin: %s", origin)
            return
        }
        w.Header().Set("Access-Control-Allow-Origin", origin)
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
        if r.Method == "OPTIONS" {
            log.Printf("Preflight request from %s allowed", origin)
            return
        }
        log.Printf("Handling request %s %s", r.Method, r.URL.Path)
        h(w, r)
    }

// / startSystemInfoServer initializes and starts the HTTP server providing system information endpoints.
func startSystemInfoServer() {
	http.HandleFunc("/system/memory", withCORS(func(w http.ResponseWriter, r *http.Request) {
		v, _ := mem.VirtualMemory()
		json.NewEncoder(w).Encode(v)
	}))

	http.HandleFunc("/system/swap", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s, _ := mem.SwapMemory()
		json.NewEncoder(w).Encode(s)
	}))

	http.HandleFunc("/system/cpu", withCORS(func(w http.ResponseWriter, r *http.Request) {
		c, _ := cpu.Info()
		json.NewEncoder(w).Encode(c)
	}))

	http.HandleFunc("/system/cpu/percent", withCORS(func(w http.ResponseWriter, r *http.Request) {
		p, _ := cpu.Percent(time.Second, true)
		json.NewEncoder(w).Encode(p)
	}))

	http.HandleFunc("/system/disk", withCORS(func(w http.ResponseWriter, r *http.Request) {
		d, _ := disk.Usage("/")
		json.NewEncoder(w).Encode(d)
	}))

	http.HandleFunc("/system/disk/partitions", withCORS(func(w http.ResponseWriter, r *http.Request) {
		parts, _ := disk.Partitions(true)
		json.NewEncoder(w).Encode(parts)
	}))

	http.HandleFunc("/system/net", withCORS(func(w http.ResponseWriter, r *http.Request) {
		io, _ := net.IOCounters(true)
		json.NewEncoder(w).Encode(io)
	}))

	http.HandleFunc("/system/net/conns", withCORS(func(w http.ResponseWriter, r *http.Request) {
		conns, _ := net.Connections("all")
		json.NewEncoder(w).Encode(conns)
	}))

	http.HandleFunc("/system/temp", withCORS(func(w http.ResponseWriter, r *http.Request) {
		temps, _ := host.SensorsTemperatures()
		json.NewEncoder(w).Encode(temps)
	}))

	http.HandleFunc("/system/host", withCORS(func(w http.ResponseWriter, r *http.Request) {
		h, _ := host.Info()
		json.NewEncoder(w).Encode(h)
	}))

	http.HandleFunc("/system/users", withCORS(func(w http.ResponseWriter, r *http.Request) {
		u, _ := host.Users()
		json.NewEncoder(w).Encode(u)
	}))

	http.HandleFunc("/system/load", withCORS(func(w http.ResponseWriter, r *http.Request) {
		l, _ := load.Avg()
		json.NewEncoder(w).Encode(l)
	}))

	http.HandleFunc("/system/processes", withCORS(func(w http.ResponseWriter, r *http.Request) {
		procs, _ := process.Processes()
		json.NewEncoder(w).Encode(procs)
	}))

	go func() {
		if *verbose {
			log.Println("System info server running at http://localhost:8080")
		}
		if err := http.ListenAndServe(":8080", nil); err != nil {
			if *verbose {
				log.Printf("System info server stopped: %v", err)
			}
		}
	}()
}

// / renderSource renders the given source URL or file path to an image using headless Chromium.
// / src: The source URL or file path to render.
// / w: Width of the rendered image.
// / h: Height of the rendered image.
// / Returns: Rendered image, error
func renderSource(src string, w, h int) (image.Image, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
				   chromedp.ExecPath(*chromiumPath),
				   chromedp.Flag("headless", true),
				   chromedp.Flag("disable-gpu", true),
				   chromedp.WindowSize(w, h),
	)

	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	if *verbose {
		enableConsoleLogging(ctx)
	}

	var buf []byte
	tasks := chromedp.Tasks{
		chromedp.Navigate(src),
		chromedp.Sleep(100 * time.Millisecond),
		chromedp.Evaluate(`loadInfo()`, nil),
		chromedp.Sleep(100 * time.Millisecond),
		chromedp.FullScreenshot(&buf, 90),
	}

	if err := chromedp.Run(ctx, tasks); err != nil {
		return nil, err
	}

	// Detects magic number
	if len(buf) >= 8 && bytes.HasPrefix(buf, []byte{0x89, 'P', 'N', 'G'}) {
		// PNG
		img, err := png.Decode(bytes.NewReader(buf))
		if err != nil {
			return nil, fmt.Errorf("fail to decode PNG: %w", err)
		}
		return img, nil
	} else if len(buf) >= 2 && buf[0] == 0xFF && buf[1] == 0xD8 {
		// JPEG
		img, err := jpeg.Decode(bytes.NewReader(buf))
		if err != nil {
			return nil, fmt.Errorf("fail to decode JPEG: %w", err)
		}
		return img, nil
	}

	return nil, fmt.Errorf("unknown format in screenshot")
}

// / main is the entry point of the application.
func main() {
	flag.Parse()
	ctx := context.Background()
	ax, err := openAX206(ctx)
	if err != nil {
		log.Fatalf("Failed to open AX206 device: %v", err)
	}
	log.Printf("AX206 device opened successfully")
	defer ax.Close()
	if *info {
		fmt.Printf("Detected resolution: %dx%d\n", ax.width, ax.height)
		return
	}
	var src string
	if *urlFlag != "" {
		src = *urlFlag
	} else if *htmlFile != "" {
		absPath, err := filepath.Abs(*htmlFile)
		if err != nil {
			log.Fatal(err)
		}
		src = "file://" + absPath
	} else {
		fmt.Println("Usage:")
		fmt.Println(" --html file.html Render a local HTML file")
		fmt.Println(" --url https://site Render an external URL")
		fmt.Println(" --loop Run in infinite loop")
		fmt.Println(" --interval=200ms Interval between renderings in loop mode")
		fmt.Println(" --format=brg565 Color format (rgb565, bgr565, brg565)")
		fmt.Println(" --endian=little Endianness (little or big)")
		fmt.Println(" --verbose Enable verbose logging")
		fmt.Println(" --rotate=90 Image Rotation (0, 90, 180, 270)")
		fmt.Println(" --info Show only display resolution")
		return
	}
	startSystemInfoServer()
	for {
		img, err := renderSource(src, ax.width, ax.height)
		if err != nil {
			log.Fatalf("Render source failed: %v", err)
		}
		img = rotateImage(img, *rotate)
		rw, rh := img.Bounds().Dx(), img.Bounds().Dy()
		buf := convertToBuffer(img, rw, rh, *format, *endian)
		if err := ax.blit(buf, 0, 0, rw, rh, 0x12); err != nil {
			log.Fatalf("Blit failed: %v", err)
		}
		if *verbose {
			log.Printf("Source %s rendered and sent (%s, %s-endian, rotate=%d).", src, *format, *endian, *rotate)
		}
		if !*loop {
			break
		}
		time.Sleep(*interval)
	}
}
