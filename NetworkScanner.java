import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.HashMap;
import java.util.List;
import java.util.Enumeration;
import java.util.ArrayList;

public class NetworkScanner extends JFrame {
    private JTextArea outputArea;
    private JTextField networkPrefixField, endIpField, portField, localIpField;
    private JButton scanButton, stopScanButton, clearScreenButton;
    private JButton enableUfwButton, disableUfwButton, listUfwButton, allowPortButton, blockPortButton;
    private JSpinner fontSizeSpinner;
    private HashMap<String, List<Integer>> activeDevices;
    private volatile boolean scanning;

    public NetworkScanner() {
        setTitle("Network Scanner");
        setSize(800, 600);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        // Output Area
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font("Monospaced", Font.PLAIN, 14));
        outputArea.setBackground(Color.BLACK);
        outputArea.setForeground(Color.GREEN);
        JScrollPane scrollPane = new JScrollPane(outputArea);
        add(scrollPane, BorderLayout.CENTER);

        // Input Panel (updated grid layout)
        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new GridLayout(4, 2)); // Adjust grid size for 4 fields

        inputPanel.add(new JLabel("Local IP Address:"));
        localIpField = new JTextField();
        localIpField.setEditable(false); // Make it non-editable
        inputPanel.add(localIpField);

        inputPanel.add(new JLabel("Network Prefix:"));
        networkPrefixField = new JTextField("192.168.1");
        inputPanel.add(networkPrefixField);

        inputPanel.add(new JLabel("Ending IP Range (last octet):"));
        endIpField = new JTextField("254");
        inputPanel.add(endIpField);

        inputPanel.add(new JLabel("Port to Allow/Block:"));
        portField = new JTextField("22");
        inputPanel.add(portField);

        add(inputPanel, BorderLayout.NORTH);

        // Buttons Panel
        JPanel buttonPanel = new JPanel();
        scanButton = new JButton("Start Network Scan");
        stopScanButton = new JButton("Stop Scanning");
        clearScreenButton = new JButton("Clear Screen");

        // UFW Buttons
        enableUfwButton = new JButton("Enable UFW");
        disableUfwButton = new JButton("Disable UFW");
        listUfwButton = new JButton("List UFW Rules");
        allowPortButton = new JButton("Allow Port");
        blockPortButton = new JButton("Block Port");

        // Font size spinner
        fontSizeSpinner = new JSpinner(new SpinnerNumberModel(14, 8, 30, 1));
        fontSizeSpinner.addChangeListener(e -> updateFontSize());

        // Add action listeners
        scanButton.addActionListener(e -> startNetworkScan());
        stopScanButton.addActionListener(e -> stopNetworkScan());
        clearScreenButton.addActionListener(e -> outputArea.setText(""));

        enableUfwButton.addActionListener(new EnableUfwAction());
        disableUfwButton.addActionListener(new DisableUfwAction());
        listUfwButton.addActionListener(new ListUfwAction());
        allowPortButton.addActionListener(new AllowPortAction());
        blockPortButton.addActionListener(new BlockPortAction());

        // Add buttons to the panel
        buttonPanel.add(scanButton);
        buttonPanel.add(stopScanButton);
        buttonPanel.add(clearScreenButton);
        buttonPanel.add(enableUfwButton);
        buttonPanel.add(disableUfwButton);
        buttonPanel.add(listUfwButton);
        buttonPanel.add(allowPortButton);
        buttonPanel.add(blockPortButton);
        buttonPanel.add(new JLabel("Font Size:"));
        buttonPanel.add(fontSizeSpinner);

        add(buttonPanel, BorderLayout.SOUTH);

        activeDevices = new HashMap<>();

        // Call displayMainIp method to set local IP address
        displayMainIp();
    }

    private void updateFontSize() {
        int fontSize = (Integer) fontSizeSpinner.getValue();
        outputArea.setFont(new Font("Monospaced", Font.PLAIN, fontSize));
    }

    private void displayMainIp() {
        try {
            // Get the system's network interfaces
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            
            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = networkInterfaces.nextElement();
                
                // Skip loopback interfaces
                if (networkInterface.isLoopback()) continue;
                
                // Get the addresses for the network interface
                Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
                
                while (inetAddresses.hasMoreElements()) {
                    InetAddress inetAddress = inetAddresses.nextElement();
                    
                    // Check if the address is an actual address (not the loopback address)
                    if (inetAddress instanceof Inet4Address) {
                        localIpField.setText(inetAddress.getHostAddress());
                        return; // Set and exit after finding the first non-loopback address
                    }
                }
            }
            
            // If no IP address is found, set error message
            localIpField.setText("Error fetching IP");
            
        } catch (SocketException e) {
            localIpField.setText("Error fetching IP");
        }
    }

    private void startNetworkScan() {
        String networkPrefix = networkPrefixField.getText();
        String endIp = endIpField.getText();

        // Disable scan button during scan
        scanButton.setEnabled(false);
        stopScanButton.setEnabled(true);
        scanning = true;

        new Thread(() -> {
            try {
                for (int i = 1; i <= Integer.parseInt(endIp); i++) {
                    if (!scanning) break;

                    String ip = networkPrefix + "." + i;
                    String command = "ping -c 1 -W 1 " + ip;

                    // Execute the ping command
                    Process process = Runtime.getRuntime().exec(command);
                    int exitCode = process.waitFor();

                    if (exitCode == 0) {
                        appendOutput("Device found at: " + ip);

                        // Now scan for open ports using nmap
                        String nmapCommand = "nmap -p 1-65535 --open " + ip;
                        Process nmapProcess = Runtime.getRuntime().exec(nmapCommand);
                        BufferedReader reader = new BufferedReader(new InputStreamReader(nmapProcess.getInputStream()));
                        String line;
                        boolean openPortsFound = false;
                        while ((line = reader.readLine()) != null) {
                            if (line.contains("open")) {
                                appendOutput("Open port found on " + ip + ": " + line.trim());
                                openPortsFound = true;
                            }
                        }
                        if (!openPortsFound) {
                            appendOutput("No open ports found on " + ip);
                        }
                    }
                }
            } catch (IOException ex) {
                appendOutput("Error during scan: " + ex.getMessage());
            } catch (InterruptedException ex) {
                appendOutput("Scan interrupted: " + ex.getMessage());
            } catch (NumberFormatException ex) {
                appendOutput("Invalid IP range specified.");
            } finally {
                appendOutput("Network scan completed.");
                scanButton.setEnabled(true);
                stopScanButton.setEnabled(false);
            }
        }).start();
    }

    private void stopNetworkScan() {
        scanning = false;
        appendOutput("Scan stopped.");
        scanButton.setEnabled(true);
        stopScanButton.setEnabled(false);
    }

    private void appendOutput(String text) {
        SwingUtilities.invokeLater(() -> outputArea.append(text + "\n"));
    }

    // UFW Actions
    private class EnableUfwAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            executeCommand("echo your_password | sudo -S ufw enable", "UFW enabled successfully.");
        }
    }

    private class DisableUfwAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            executeCommand("echo your_password | sudo -S ufw disable", "UFW disabled successfully.");
        }
    }

    private class ListUfwAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            executeCommand("echo your_password | sudo -S ufw status numbered", "UFW Rules:");
        }
    }

    private class AllowPortAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String port = portField.getText();
            executeCommand("echo your_password | sudo -S ufw allow " + port, "Allowed port " + port);
        }
    }

    private class BlockPortAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String port = portField.getText();
            executeCommand("echo your_password | sudo -S ufw deny " + port, "Blocked port " + port);
        }
    }

    private void executeCommand(String command, String successMessage) {
        new Thread(() -> {
            try {
                Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    appendOutput(line);
                }
                process.waitFor();
                appendOutput(successMessage);
            } catch (IOException | InterruptedException ex) {
                appendOutput("Error executing command: " + ex.getMessage());
            }
        }).start();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            NetworkScanner scanner = new NetworkScanner();
            scanner.setVisible(true);
        });
    }
}
