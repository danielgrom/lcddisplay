# LCD Display Program
This project provides a Go program to render HTML or external URLs using **chromedp**, convert the image to the correct pixel format, and send it to an AX206-based LCD display via USB, such as those available on AliExpress.

## Features
- Render local HTML files (`--html file.html`) or external URLs (`--url https://site.com`).
- Display information about the LCD resolution (`--info`).
- Continuous rendering loop (`--loop`) with adjustable interval (`--interval=200ms`).
- Support for multiple color formats: `rgb565`, `bgr565`, `brg565`.
- Endianness control: `little` or `big`.

## Usage
```bash
# Render a local HTML file once
./lcddisplay --html page.html

# Render an external URL in loop mode with 200ms interval
./lcddisplay --url https://example.com --loop --interval=200ms

# Show only LCD resolution
./lcddisplay --info
