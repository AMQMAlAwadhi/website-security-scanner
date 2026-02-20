# Website Security Scanner

A comprehensive security analysis tool specifically designed for low-code platforms, developed as part of a Bachelor thesis on "Low-Code Platforms for E-commerce: Comparative Security Analysis".

## Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd website_security_scanner

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Start the web interface
wss-web

# Open in browser
http://localhost:5000
```

## Project Structure

```
website_security_scanner/
├── src/                     # Source code
├── tests/                   # Test suite
├── docs/                    # Documentation
├── examples/                # Example files and configurations
├── docker/                 # Docker configuration
├── config/                 # Configuration files
├── scripts/                # Utility scripts
├── logs/                   # Runtime logs
├── requirements.txt         # Python dependencies
├── pyproject.toml         # Project configuration
├── .env.example           # Environment template
└── README.md              # This file
```

## Documentation

- **[Full Documentation](docs/README.md)** - Complete documentation index
- **[Development Guide](docs/DEVELOPMENT.md)** - Development setup and contributions
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment instructions
- **[API Reference](docs/API.md)** - Complete API documentation

## License

This project is developed for academic research purposes. Please respect the terms of use of the platforms being analyzed and use this tool responsibly.
