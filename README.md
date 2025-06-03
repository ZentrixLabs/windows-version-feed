# Windows Version Feed

This repository is a JSON feed repository that provides up-to-date Windows OS build information and CVE mappings by Patch Validation (ZentrixLabs).

## Purpose

This project collects and organizes Microsoft’s monthly CVRF (Common Vulnerability Reporting Framework) data and extracts:

- **Windows Versions:** A dynamic mapping of Windows Server, Windows 10, and Windows 11 product names to their current build numbers and the latest KB fixes.
- **CVE Mappings:** A comprehensive mapping of CVEs to the relevant KB fixes, product names, and builds.

## Files

- **windows-versions-current.json** — Contains the **latest OS build information**, including build number, latest KB, and release date. This file is updated automatically.
- **CVE_KB_Mapping_current.json** — Contains the **latest CVE-to-KB mappings** for Windows systems.
- **Historical Archives:**
  - **windows-versions.json** — Monthly snapshot of Windows version data (archived monthly).
  - **CVE_KB_Mapping_YYYY-MMM.json** — Monthly snapshot of CVE-to-KB mappings (e.g., `CVE_KB_Mapping_2025-May.json`).

## Usage

These JSON files can be integrated into automated workflows, dashboards, or vulnerability management systems to:
- Validate current patch levels for Windows systems
- Correlate CVEs to specific Windows builds and KBs
- Enhance visibility into Microsoft’s patching cycle

For the latest data, always use:

- windows-versions-current.json
- CVE_KB_Mapping_current.json

For historical reference, archived files are available for previous months.

## Automation

This repository uses a GitHub Actions workflow to update the JSON files:
- **Schedule:** Every Wednesday at 00:00 UTC
- **Manual Trigger:** On push to `main` (when changes are made to `generate_os_cve_data.ps1` or `kb_cve_data.csv`).
- **Workflow File:** `.github/workflows/update-windows-versions.yml`

## License

This project is open source and licensed under the [MIT License](LICENSE).

## Maintainers

Mike (at) ZentrixLabs.
