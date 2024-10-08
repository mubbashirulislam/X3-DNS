
# X3-DNS

X3-DNS is a robust and user-friendly DNS vulnerability assessment tool designed to help users identify and mitigate potential security risks in their domain's DNS configuration. This tool performs comprehensive checks for common DNS vulnerabilities, including SPF, DKIM, DMARC, DNSSEC, MX, and CAA records, providing detailed results and actionable recommendations to enhance DNS security.

## Features

- **SPF Record Validation**: Ensures the presence and correctness of SPF records to prevent email spoofing.
- **DKIM Record Check**: Searches for DKIM records using common selectors to verify email integrity.
- **DMARC Record Verification**: Confirms the existence of DMARC records to enforce email authentication policies.
- **DNSSEC Configuration Check**: Validates DNSSEC setup to protect against DNS spoofing and cache poisoning.
- **MX Record Validation**: Checks for valid MX records to ensure reliable email delivery.
- **CAA Record Validation**: Ensures the presence of CAA records to restrict certificate issuance to authorized CAs.

## How It Works

X3-DNS leverages the `dnspython` library to perform DNS queries and validate the presence and correctness of various DNS records. The tool is built with a user-friendly interface using `tkinter` and `ttkthemes`, allowing users to easily input domains, select vulnerabilities to check, and view results in a structured format.

## Installation

To run X3-DNS from source, follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/mubbashirulislam/X3-DNS.git
   cd X3-DNS
   ```

2. **Install Requirements**:
   Ensure you have Python 3.x installed. Then, install the required Python packages using pip:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Tool**:
   Execute the tool using Python:
   ```bash
   python X3-DNS.py
   ```

## Requirements

The tool requires the following Python packages, which are listed in `requirements.txt`:

- `tkinter`: For building the graphical user interface.
- `ttkthemes`: For applying modern themes to the tkinter interface.
- `dnspython`: For performing DNS queries and record validation.

## Executable Version

For users who prefer not to install Python and dependencies, an executable version of X3-DNS is available. This version can be run out of the box on Windows systems without any additional setup.

- **Download the Executable**: [X3-DNS.exe](https://github.com/mubbashirulislam/X3-DNS/X3-DNS.exe)
- **Run the Executable**: Simply double-click the `X3-DNS.exe` file to launch the tool.

## Usage

1. **Enter Domain**: Input the domain you wish to check in the provided text box.
2. **Select Vulnerabilities**: Choose which DNS vulnerabilities to check by selecting the appropriate checkboxes.
3. **Check DNS**: Click the "Check DNS" button to start the analysis.
4. **View Results**: The results will be displayed in the scrollable text area, highlighting any vulnerabilities found.
5. **Save Report**: Optionally, save the results to a text file for further analysis.

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, feel free to open an issue or submit a pull request. Please ensure your contributions adhere to the project's coding standards and include appropriate tests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or support, please contact [Your Name](mailto:your.email@example.com).

