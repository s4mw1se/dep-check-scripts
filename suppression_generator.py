from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

class Suppression:
    def __init__(self, package_url, days_to_suppress, note, cve_list=None, vulnerability_names=None):
        self.package_url = package_url
        self.until_date = ( datetime.now() + timedelta(days=days_to_suppress)).strftime('%Y-%m-%dZ')
        self.note = note
        self.cve_list = cve_list if cve_list else []
        self.vulnerability_names = vulnerability_names if vulnerability_names else []

    def generate_xml(self):
        suppress = ET.Element("suppress", until=self.until_date)
        
        notes = ET.SubElement(suppress, "notes")
        notes.text = f"<![CDATA[\n{self.note}\n]]>"
        
        package_url = ET.SubElement(suppress, "packageUrl", regex="true")
        package_url.text = f"^{self.package_url}$"

        for cve in self.cve_list:
            cve_element = ET.SubElement(suppress, "cve")
            cve_element.text = cve

        for vulnerability_name in self.vulnerability_names:
            vulnerability_name_element = ET.SubElement(suppress, "vulnerabilityName", regex="true")
            vulnerability_name_element.text = vulnerability_name

        return ET.tostring(suppress, encoding="utf8", method="xml")

# Example usage:
s = Suppression(
    package_url="pkg:npm/socket.io@3.1.2",
    days_to_suppress=30,
    note="a note about the suppression",
    cve_list=["CVE-2013-1337", "CVE-2025-1337"],
    vulnerability_names=["GHSA-d2f23-3ffe", "GHSA-yd3e2-3ffe"]
)

print(s.generate_xml())
