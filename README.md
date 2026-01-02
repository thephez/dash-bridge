# Dash Bridge

A non-custodial bridge for converting Dash Core funds to Dash Platform credits.

## Features

- Client-side only - all cryptographic operations happen in your browser
- Supports both testnet and mainnet (via `?network=mainnet` URL parameter)
- HD wallet support with BIP39 mnemonic generation
- QR code generation for deposit addresses

## Development

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Deployment

This project automatically deploys to GitHub Pages on push to `main` via GitHub Actions.

## License

MIT
