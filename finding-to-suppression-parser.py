#Parses JUNIT report and creates xml for suppression file for each package with vulnerabilities

import xml.etree.ElementTree as ET
import re

class Vulnerability:
  def __init__(self, id, pkg, failure_string):
      self.failure_string = failure_string
      self.id = id
      self.pkg = pkg
      self.severity = None
      self.score = None
      self.id = None
      self.type = None
      
  def parse_failure_string(self):
    if self.failure_string is None:
      return
    
    # Parse the failure string
    # Get the severity
    severity = re.search(r"Severity: (\w+)", self.failure_string)
    if severity:
      self.severity = severity.group(1)
      
    # Get the score
    score = re.search(r"Score: (\d+\.\d+)", self.failure_string)
    if score:
      self.score = score.group(1)
      
  def to_suppresion_xml(self):
    # Create the suppression XML
    suppression = ET.Element("suppress")
    notes = ET.SubElement(suppression, "notes")
    notes.text = f"{self.severity} Automatic Suppressesion for {self.pkg}."
    packageUrl = ET.SubElement(suppression, "packageUrl")
    packageUrl.set("regex", "true")
    packageUrl.text = f"^{self.pkg}$"
  
    vulnerabilityName = ET.SubElement(suppression, "vulnerabilityName")
    vulnerabilityName.text = f"{self.id}"
    return suppression    

class Suppression:
  def __init__(self, testsuite: ET.Element):
      self.testsuite_xml = testsuite
      self.vulberanilities = []
    
  def parse_testcases(self, testsuite: ET.Element):
    vulnerabilities = []
    for testcase in testsuite.findall('testcase'):
      vuln_id = testcase.get('classname')
      package = testcase.get('name')
      failure_string = testcase.find('failure')
      vulnerabilities.append(Vulnerability(vuln_id, package, failure_string))
        
          
# The XML string provided by the user
def junit_failure_parser():
  """ Parse the JUnit XML file and return the testsuite elements that have failures. """
  #open and read junit xml file
  with open("src/dependency-check-junit.xml", "r") as file:
      xml_data = file.read()

  suppressions = []
  # Parse the XML
  root = ET.fromstring(xml_data)

  # Create a new XML tree for output
  new_root = ET.Element("testsuites")

  # Iterate through each testsuite element
  for testsuite in root.findall('testsuite'):
      get_failures_attribute = testsuite.get('failures')
      if get_failures_attribute is None:
          continue
      
      failures = int(get_failures_attribute)
      if failures > 0:
          suppressions.append(Suppression(testsuite))
          for testcase in testsuite.findall('testcase'):
              for system_out in testcase.findall('system-out'):
                  testcase.remove(system_out)
              for system_err in testcase.findall('system-err'):
                  testcase.remove(system_err)
          suppressions.append(Suppression(testsuite))
          new_root.append(testsuite)

  # Convert the new tree to a string
  new_xml_str = ET.tostring(new_root, encoding='utf-8', method='xml').decode()

  # Output the result
  return suppressions, new_xml_str

suppression_list, new_xml = junit_failure_parser()

print(suppression_list)

