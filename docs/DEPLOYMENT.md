# Documentation Deployment Guide

This guide explains how to deploy the Firepan documentation to your website.

## Overview

The Firepan documentation is written in Markdown format and can be deployed to any static site generator or documentation platform.

## Documentation Structure

```
docs/
├── README.md                  # Documentation hub/navigation
├── QUICK_START.md            # Getting started guide
├── API_REFERENCE.md          # Complete API documentation
├── DEVELOPER_GUIDE.md        # Development setup and guidelines
├── MODULES.md                # Technical module reference
├── ARCHITECTURE.md           # Architecture deep dive
├── SURFACE_SCAN.md           # Surface scan feature
├── cloud_storage_guide.md    # Cloud storage setup
├── cost_tracking.md          # Cost monitoring
├── railway_deployment.md     # Railway deployment
└── architecture/             # Detailed architecture docs
    ├── README.md
    ├── saas_architecture.md
    ├── technical_overview.md
    ├── cloud_storage.md
    ├── headless_agent.md
    ├── coverage_tracking.md
    └── pr_reporter.md

CONTRIBUTING.md               # Root-level contribution guide
```

## Deployment Options

### Option 1: GitHub Pages

The simplest option if your docs are in a GitHub repository:

1. **Enable GitHub Pages:**
   - Go to repository Settings → Pages
   - Select source: "Deploy from a branch"
   - Choose branch: `main` (or your default branch)
   - Select folder: `/docs`

2. **Access your docs:**
   - URL: `https://firepan-labs.github.io/hound/`
   - Add to your main site: `https://firepan.com/developers/documentation/`

3. **Custom domain (optional):**
   - Add `CNAME` file to docs folder with: `docs.firepan.com`
   - Configure DNS settings

### Option 2: Docusaurus (Recommended)

Docusaurus is a modern documentation framework that works great with Markdown:

1. **Install Docusaurus:**
   ```bash
   npx create-docusaurus@latest firepan-docs classic
   cd firepan-docs
   ```

2. **Copy documentation:**
   ```bash
   # Copy all markdown files to Docusaurus docs folder
   cp -r ../hound/docs/* docs/
   cp ../hound/CONTRIBUTING.md docs/
   ```

3. **Configure `docusaurus.config.js`:**
   ```javascript
   module.exports = {
     title: 'Firepan Documentation',
     tagline: 'Autonomous security analysis for code',
     url: 'https://firepan.com',
     baseUrl: '/developers/documentation/',
     onBrokenLinks: 'warn',
     favicon: 'img/favicon.ico',
     organizationName: 'firepan-labs',
     projectName: 'hound',
     
     themeConfig: {
       navbar: {
         title: 'Firepan',
         items: [
           {
             type: 'doc',
             docId: 'QUICK_START',
             position: 'left',
             label: 'Quick Start',
           },
           {
             type: 'doc',
             docId: 'API_REFERENCE',
             position: 'left',
             label: 'API',
           },
           {
             type: 'doc',
             docId: 'DEVELOPER_GUIDE',
             position: 'left',
             label: 'Developers',
           },
         ],
       },
       footer: {
         style: 'dark',
         links: [
           {
             title: 'Documentation',
             items: [
               {label: 'Quick Start', to: '/docs/QUICK_START'},
               {label: 'API Reference', to: '/docs/API_REFERENCE'},
               {label: 'Architecture', to: '/docs/ARCHITECTURE'},
             ],
           },
         ],
         copyright: `Copyright © ${new Date().getFullYear()} Firepan Labs`,
       },
     },
   };
   ```

4. **Build and deploy:**
   ```bash
   npm run build
   npm run serve  # Test locally
   
   # Deploy to your hosting
   rsync -avz build/ user@firepan.com:/var/www/developers/documentation/
   ```

### Option 3: VitePress

VitePress is a Vue-powered static site generator:

1. **Install VitePress:**
   ```bash
   mkdir firepan-docs && cd firepan-docs
   npm init -y
   npm install -D vitepress
   ```

2. **Setup structure:**
   ```bash
   mkdir docs
   cp -r ../hound/docs/* docs/
   ```

3. **Configure `.vitepress/config.js`:**
   ```javascript
   export default {
     title: 'Firepan Documentation',
     description: 'Security analysis platform documentation',
     base: '/developers/documentation/',
     
     themeConfig: {
       nav: [
         { text: 'Quick Start', link: '/QUICK_START' },
         { text: 'API', link: '/API_REFERENCE' },
         { text: 'Guide', link: '/DEVELOPER_GUIDE' }
       ],
       
       sidebar: [
         {
           text: 'Getting Started',
           items: [
             { text: 'Quick Start', link: '/QUICK_START' },
             { text: 'Architecture', link: '/ARCHITECTURE' }
           ]
         },
         {
           text: 'Reference',
           items: [
             { text: 'API Reference', link: '/API_REFERENCE' },
             { text: 'Modules', link: '/MODULES' },
             { text: 'Developer Guide', link: '/DEVELOPER_GUIDE' }
           ]
         }
       ]
     }
   }
   ```

4. **Build:**
   ```bash
   npm run docs:build
   # Output in .vitepress/dist
   ```

### Option 4: MkDocs

Python-based documentation generator:

1. **Install MkDocs:**
   ```bash
   pip install mkdocs mkdocs-material
   ```

2. **Create `mkdocs.yml`:**
   ```yaml
   site_name: Firepan Documentation
   site_url: https://firepan.com/developers/documentation/
   theme:
     name: material
     palette:
       primary: blue
       accent: indigo
   
   nav:
     - Home: README.md
     - Quick Start: QUICK_START.md
     - API Reference: API_REFERENCE.md
     - Developer Guide: DEVELOPER_GUIDE.md
     - Architecture: ARCHITECTURE.md
     - Modules: MODULES.md
     - Architecture Deep Dive:
       - Overview: architecture/README.md
       - SaaS Architecture: architecture/saas_architecture.md
       - Technical Overview: architecture/technical_overview.md
     - Contributing: ../CONTRIBUTING.md
   ```

3. **Copy docs:**
   ```bash
   mkdir docs
   cp -r ../hound/docs/* docs/
   ```

4. **Build and serve:**
   ```bash
   mkdocs serve  # Test locally at http://localhost:8000
   mkdocs build  # Build to site/
   ```

### Option 5: Direct Integration

For direct integration into your existing website:

1. **Convert Markdown to HTML:**
   ```bash
   # Using pandoc
   for file in docs/*.md; do
     pandoc "$file" -o "${file%.md}.html" --standalone --css=style.css
   done
   ```

2. **Or use a Markdown renderer in your frontend:**
   ```javascript
   // React example
   import ReactMarkdown from 'react-markdown'
   import remarkGfm from 'remark-gfm'
   
   function Documentation() {
     const [content, setContent] = useState('')
     
     useEffect(() => {
       fetch('/api/docs/QUICK_START.md')
         .then(res => res.text())
         .then(text => setContent(text))
     }, [])
     
     return (
       <ReactMarkdown remarkPlugins={[remarkGfm]}>
         {content}
       </ReactMarkdown>
     )
   }
   ```

3. **Setup API to serve markdown:**
   ```javascript
   // Express.js example
   const express = require('express')
   const fs = require('fs')
   const path = require('path')
   
   app.get('/api/docs/:filename', (req, res) => {
     const file = path.join(__dirname, 'docs', req.params.filename)
     fs.readFile(file, 'utf8', (err, data) => {
       if (err) return res.status(404).send('Not found')
       res.type('text/markdown').send(data)
     })
   })
   ```

## Recommended Setup for firepan.com/developers/documentation/

Based on your URL structure, here's the recommended approach:

### 1. Use Docusaurus or VitePress

Both are excellent for modern documentation sites and integrate well with existing websites.

**Pros:**
- Beautiful, professional UI out of the box
- Built-in search functionality
- Responsive design
- Fast performance
- Easy to maintain

### 2. File Structure Mapping

Map the documentation to your URL structure:

```
https://firepan.com/developers/documentation/
├── /quick-start          → QUICK_START.md
├── /api                  → API_REFERENCE.md
├── /developer-guide      → DEVELOPER_GUIDE.md
├── /architecture         → ARCHITECTURE.md
├── /modules              → MODULES.md
└── /contributing         → CONTRIBUTING.md
```

### 3. Styling Considerations

The markdown files are ready to use, but you may want to:

1. **Add custom CSS** to match firepan.com branding
2. **Update code highlighting** themes
3. **Add custom components** for callouts/alerts
4. **Configure navigation** to match your site structure

### 4. Search Integration

Add search functionality:

- **Docusaurus**: Built-in search with Algolia
- **VitePress**: Built-in local search
- **Custom**: Integrate with your existing search

## Next Steps

1. **Choose a deployment method** from the options above
2. **Copy the documentation files** to your chosen platform
3. **Configure navigation and styling** to match your brand
4. **Set up continuous deployment** from this repository
5. **Add redirects** from old URLs if applicable

## Continuous Deployment

Set up automatic updates when documentation changes:

### GitHub Actions Example

```yaml
name: Deploy Documentation

on:
  push:
    branches: [main]
    paths:
      - 'docs/**'
      - 'CONTRIBUTING.md'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Build docs
        run: |
          cd docusaurus-site
          npm install
          npm run build
      
      - name: Deploy to production
        run: |
          rsync -avz build/ ${{ secrets.DEPLOY_USER }}@firepan.com:/var/www/developers/documentation/
```

## Accessing the Documentation

The documentation is available in this repository at:

- **Location**: `/docs/` directory
- **Entry point**: `docs/README.md` (navigation hub)
- **Format**: GitHub Flavored Markdown (GFM)

You can:
1. **Clone this repository** and use the files directly
2. **Download as ZIP** from GitHub
3. **Link as submodule** to your website repository
4. **Copy files** to your documentation platform

## Support

For questions about deploying the documentation:
- Check the [Developer Guide](DEVELOPER_GUIDE.md)
- See [Contributing](../CONTRIBUTING.md)
- Open an issue in the repository

## Preview

To preview locally before deployment:

```bash
# Simple Python server
cd docs
python -m http.server 8000

# Or Node.js
npx serve docs

# Then visit http://localhost:8000
```

Note: Some features (like internal links) may not work perfectly with a simple HTTP server. Use a documentation framework for the best experience.
