import QRCode from 'qrcode';

/**
 * Generate a QR code as a data URL
 */
export async function generateQRCodeDataUrl(
  data: string,
  size: number = 200
): Promise<string> {
  return QRCode.toDataURL(data, {
    width: size,
    margin: 2,
    color: {
      dark: '#000000',
      light: '#ffffff',
    },
  });
}

/**
 * Create a QR code image element
 */
export async function createQRCodeElement(
  data: string,
  size: number = 200
): Promise<HTMLImageElement> {
  const dataUrl = await generateQRCodeDataUrl(data, size);

  const img = document.createElement('img');
  img.src = dataUrl;
  img.alt = 'QR Code';
  img.width = size;
  img.height = size;

  return img;
}

/**
 * Render QR code to a canvas element
 */
export async function renderQRCodeToCanvas(
  canvas: HTMLCanvasElement,
  data: string
): Promise<void> {
  await QRCode.toCanvas(canvas, data, {
    width: canvas.width,
    margin: 2,
  });
}
