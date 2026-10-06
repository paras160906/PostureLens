---
name: Obsidian Sentinel
colors:
  surface: '#001428'
  surface-dim: '#001428'
  surface-bright: '#253b53'
  surface-container-lowest: '#000f20'
  surface-container-low: '#031d34'
  surface-container: '#072138'
  surface-container-high: '#142b43'
  surface-container-highest: '#20364e'
  on-surface: '#d1e4ff'
  on-surface-variant: '#bbcac5'
  inverse-surface: '#d1e4ff'
  inverse-on-surface: '#1b324a'
  outline: '#869490'
  outline-variant: '#3c4946'
  surface-tint: '#59dbc7'
  primary: '#59dbc7'
  on-primary: '#003731'
  primary-container: '#00a896'
  on-primary-container: '#00352e'
  inverse-primary: '#006b5f'
  secondary: '#afc9ea'
  on-secondary: '#17324d'
  secondary-container: '#2f4865'
  on-secondary-container: '#9eb7d8'
  tertiary: '#ffb3b3'
  on-tertiary: '#680014'
  tertiary-container: '#ff5e68'
  on-tertiary-container: '#640013'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#79f7e3'
  primary-fixed-dim: '#59dbc7'
  on-primary-fixed: '#00201c'
  on-primary-fixed-variant: '#005047'
  secondary-fixed: '#d1e4ff'
  secondary-fixed-dim: '#afc9ea'
  on-secondary-fixed: '#001d36'
  on-secondary-fixed-variant: '#2f4865'
  tertiary-fixed: '#ffdad9'
  tertiary-fixed-dim: '#ffb3b3'
  on-tertiary-fixed: '#400009'
  on-tertiary-fixed-variant: '#920021'
  background: '#001428'
  on-background: '#d1e4ff'
  surface-variant: '#20364e'
typography:
  headline-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  headline-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.05em
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  base: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 40px
  gutter: 20px
  sidebar-width: 260px
---

## Brand & Style

The design system is engineered for deep-stack visibility and high-stakes decision-making. It targets DevSecOps professionals who require immediate clarity amidst complex data. The aesthetic is a refined **Modern-Corporate** blend with **Technical/Minimalist** influences, emphasizing structural integrity and data density without clutter.

The UI evokes a sense of "Mission Control"—stable, authoritative, and precise. It utilizes a sophisticated dark theme to reduce eye strain during prolonged monitoring, using luminosity and subtle glows to pull attention toward critical security vulnerabilities.

## Colors

The palette is anchored by a deep navy foundation to establish a professional, secure environment. 

- **Primary (Teal):** Used for primary actions, success states, and safe status indicators.
- **Surface & Borders:** Tonal variations of navy/charcoal create depth without relying on heavy shadows.
- **Semantic Logic:** Severity is strictly enforced via color. Critical (#E84855) and Warning (#F2A65A) are reserved for active threats.
- **Typography:** High-contrast off-white is used for readability, while medium-emphasis blue-greys are used for metadata and labels to maintain visual hierarchy.

## Typography

This design system utilizes a dual-font strategy. **Inter** provides high-legibility for the core interface, while **JetBrains Mono** is employed for technical metadata, status badges, and code snippets to reinforce the developer-centric nature of the tool.

- **Headlines:** Keep weights at 600 (Semi-Bold) for clear section anchoring.
- **Labels:** Always use the Monospaced font for status badges and ID strings (e.g., CVE IDs, Container Hashes) to ensure character alignment.
- **Scaling:** Mobile typography drops the scale significantly to prioritize data density in portrait views.

## Layout & Spacing

The layout follows a **Fixed-Fluid Hybrid** model. A fixed-width left navigation sidebar (260px) anchors the experience, while the main content area utilizes a fluid grid that optimizes for wide-screen monitoring dashboards.

- **Grid:** Use a 12-column grid for dashboard widgets. Widgets typically span 3, 4, 6, or 12 columns.
- **Rhythm:** An 8px base unit drives all padding and margins. 
- **Density:** High-density data tables should use 8px vertical cell padding, while high-level overview cards use 24px padding to allow for visual breathing room.
- **Breakpoints:**
  - Desktop: 1200px+
  - Tablet: 768px - 1199px (Sidebar collapses to icons)
  - Mobile: <768px (Sidebar hidden, accessible via hamburger; cards stack vertically)

## Elevation & Depth

This design system eschews traditional shadows in favor of **Tonal Layering** and **Low-Contrast Outlines**.

- **Level 0 (Background):** #0D1B2A - The base layer.
- **Level 1 (Cards/Sidebar):** #1B263B - Elevated surfaces. Use a 1px solid border of #415A77 to define edges.
- **Level 2 (Modals/Popovers):** #24304A - The highest surface. Use a soft 16px blur shadow with 20% opacity black to separate from the main UI.
- **Glow Effects:** Critical status indicators (Red) feature a 4px outer glow of the same color at 30% opacity to simulate an "active alarm" state.

## Shapes

The shape language is "Soft-Technical." Elements use a subtle 4px radius (`rounded-sm`) for standard components like buttons and inputs. 

- **Cards:** Use `rounded-lg` (8px) for a modern feel.
- **Status Badges:** Use `rounded-sm` (4px) or Sharp (0px) to maintain a rigid, professional look. 
- **Toggle Switches:** Use fully pill-shaped (rounded-full) handles to provide a clear interactive affordance.

## Components

### Buttons
- **Primary:** Solid Teal (#00A896) with High Emphasis text.
- **Secondary:** Outlined with #415A77, text in Medium Emphasis.
- **Ghost:** No background or border, Teal text. Reserved for low-priority actions in tables.

### Status Badges
Badges use a "Tinted-Fill" style: a 10% opacity background of the semantic color with a 100% opacity text color in the monospaced font. 
- *Example:* Critical badge has #E84855 at 10% BG and #E84855 text.

### Data Tables
- Header row: #1B263B background with #778DA9 uppercase monospaced text.
- Row hover: Subtle highlight using #24304A.
- Border-bottom: 1px solid #415A77.

### Code Snippets
Blocks use the darkest navy (#09121C) with a 1px #415A77 border. Syntax highlighting should follow a "Night Owl" or "Dracula" inspired sub-palette to maintain the technical vibe.

### Input Fields
Dark backgrounds (#0D1B2A) with a 1px #415A77 border. On focus, the border transitions to Teal (#00A896) with a 2px outer glow.