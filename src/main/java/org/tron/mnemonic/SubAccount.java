package org.tron.mnemonic;

import com.typesafe.config.Config;
import lombok.Builder;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import org.jline.utils.AttributedStringBuilder;
import org.jline.utils.AttributedStyle;
import org.jline.utils.InfoCmp;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.sm2.SM2;
import org.tron.core.config.Configuration;
import org.tron.core.exception.CipherException;
import org.tron.keystore.WalletFile;
import org.tron.walletserver.WalletApi;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SubAccount {
  private static volatile SubAccount instance;

  private final Terminal terminal;
  private final LineReader reader;
  private final List<WalletAddress> addresses;
  private final int pageSize = 10;
  private int currentPage = 0;
  private final int totalPages;
  private String mnemonic;
  private byte[] password;
  private static boolean isEckey = true;

  private static final String PATH_PREFIX = "m/44'/195'/";
  private static final String PATH_MIDDLE = "'/0/";

  public static SubAccount getInstance(byte[] password, String mnemonic) throws Exception {
    if (instance == null) {
      synchronized (SubAccount.class) {
        if (instance == null) {
          instance = new SubAccount(password, mnemonic);
        }
      }
    }
    return instance;
  }

  @Data
  @Builder
  private static class WalletAddress {
    private final int pathIndex;
    private final String address;
    private final byte[] privateKey;
    private boolean generated;

    public String getDisplayString() {
      String path = MnemonicUtils.formatPathIndex2Path(pathIndex);
      return String.format("%-42s %-25s %s",
          address,
          path,
          generated ? "✓" : "×");
    }

    public String getDetailString() {
      String path = MnemonicUtils.formatPathIndex2Path(pathIndex);
      return String.format("Address: %s Path: %s Status: %s",
          address,
          path,
          generated ? "Generated" : "Not Generated");
    }
  }

  private SubAccount(byte[] password, String mnemonic) throws Exception {
    Config config = Configuration.getByPath("config.conf");
    if (config.hasPath("crypto.engine")) {
      isEckey = config.getString("crypto.engine").equalsIgnoreCase("eckey");
    }
    this.mnemonic = mnemonic;
    this.password = password;
    this.terminal = TerminalBuilder.builder()
        .system(true)
        .build();
    this.reader = LineReaderBuilder.builder()
        .terminal(terminal)
        .build();
    this.addresses = initializeAddresses();
    this.totalPages = (addresses.size() + pageSize - 1) / pageSize;
    generateAddresses(mnemonic);
  }

  private List<WalletAddress> initializeAddresses() {
    List<WalletAddress> result = new ArrayList<>();
    for (int i = 0; i <= 99; i++) {
      //String path = String.format("m/44'/195'/0'/0/%d", i);
      result.add(WalletAddress.builder()
          .pathIndex(i)
          .address("")
          .privateKey("".getBytes())
          .generated(false)
          .build());
    }
    return result;
  }

  private void generateAddresses(String mnemonic) {
    for (int i = 0; i <= 99; i++) {
      try {
        WalletAddress newAddress = generateWalletAddress(mnemonic, addresses.get(i).getPathIndex());
        newAddress.setGenerated(MnemonicUtils.generatedAddress(newAddress.getAddress()));
        addresses.set(i, newAddress);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  private WalletAddress generateWalletAddress(String mnemonic, int pathIndex) {
    List<String> words = MnemonicUtils.stringToMnemonicWords(mnemonic);
    byte[] privateKey = MnemonicUtils.getPrivateKeyFromMnemonicByPath(words, pathIndex);
    String address = "";
    if (isEckey) {
      ECKey ecKey = ECKey.fromPrivate(privateKey);
      address = WalletApi.encode58Check(ecKey.getAddress());
    } else {
      SM2 sm2 = SM2.fromPrivate(privateKey);
      address = WalletApi.encode58Check(sm2.getAddress());
    }

    return WalletAddress.builder()
        .pathIndex(pathIndex)
        .address(address)
        .privateKey(privateKey)
        .generated(false)
        .build();
  }

  private WalletAddress generateWalletAddressByCustomPath(String mnemonic, String pathFull) {
    List<String> words = MnemonicUtils.stringToMnemonicWords(mnemonic);
    byte[] privateKey = MnemonicUtils.getPrivateKeyFromMnemonicByCustomPath(words, pathFull);
    String address = "";
    if (isEckey) {
      ECKey ecKey = ECKey.fromPrivate(privateKey);
      address = WalletApi.encode58Check(ecKey.getAddress());
    } else {
      SM2 sm2 = SM2.fromPrivate(privateKey);
      address = WalletApi.encode58Check(sm2.getAddress());
    }

    return WalletAddress.builder()
        .pathIndex(-1)
        .address(address)
        .privateKey(privateKey)
        .generated(true)
        .build();
  }

  private void printProgress(String message) {
    terminal.writer().print("\r" + message);
    terminal.writer().flush();
  }

  private void clearScreen() throws Exception {
    terminal.puts(InfoCmp.Capability.clear_screen);
    terminal.flush();
  }

  private void displayCurrentPage() throws Exception {
    clearScreen();
    AttributedStringBuilder asb = new AttributedStringBuilder();
    asb.append("\n\n=== Address List - Page ")
        .append(String.valueOf(currentPage + 1))
        .append(" of ")
        .append(String.valueOf(totalPages))
        .append(" ===\n\n");

    asb.append(String.format("%-4s %-42s %-25s %s\n",
        "No.", "Address", "Path", "Status"));
    asb.append(StringUtils.repeat("-", 80)).append("\n");

    int start = currentPage * pageSize;
    int end = Math.min(start + pageSize, addresses.size());

    for (int i = start; i < end; i++) {
      asb.append(String.format("%-4d %s\n",
          i + 1,
          addresses.get(i).getDisplayString()));
    }
    asb.append("Commands: [P] Previous page [N] Next page [S] Select address (enter number) [Q] Quit Enter command: ");

    terminal.writer().print(asb.toAnsi());
    terminal.flush();
  }

  private void handleSelectAddress() throws Exception {
    int start = currentPage * pageSize;
    int end = Math.min(start + pageSize, addresses.size());
    String input = reader.readLine("Enter address number (" +
        (start + 1) + "-" + end + "): ");
    try {
      int index = Integer.parseInt(input.trim()) - 1;
      if (index >= start && index < end) {
        WalletAddress selected = addresses.get(index);
        if (!selected.isGenerated()) {
          WalletFile walletFile = WalletApi.CreateWalletFile(password
              , selected.privateKey
              , MnemonicUtils.stringToMnemonicWords(mnemonic)
          );
          String keystoreName = WalletApi.store2Keystore(walletFile);
          System.out.println("Generate a sub account successful, keystore file name is " + keystoreName);
          selected.setGenerated(true);
          return;
        }
        clearScreen();
        terminal.writer().println("\n=== Selected Address ===");
        terminal.writer().println(selected.getDetailString());
        terminal.writer().println("Press Enter to continue...");
        terminal.flush();
        reader.readLine();
      } else {
        showError("Invalid address number!");
      }
    } catch (NumberFormatException e) {
      showError("Invalid input!");
    }
  }

  private void showError(String message) {
    terminal.writer().println("\n" + message);
    terminal.writer().println("Press Enter to continue...");
    terminal.flush();
    reader.readLine();
  }

  public void start() throws Exception {
    while (true) {
      displayCurrentPage();
      String command = reader.readLine().trim().toUpperCase();

      switch (command) {
        case "P":
          if (currentPage > 0) {
            currentPage--;
          } else {
            showError("Already at first page!");
          }
          break;
        case "N":
          if (currentPage < totalPages - 1) {
            currentPage++;
          } else {
            showError("Already at last page!");
          }
          break;
        case "S":
          handleSelectAddress();
          break;
        case "Q":
          return;
        default:
          showError("Invalid command!");
          break;
      }
    }
  }

  public void generateByCustomPath() throws Exception {
    try {
      String pathFull = handlePathInput();
      generateSubAccountByCustomPath(pathFull);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void generateSubAccountByCustomPath(String path) throws CipherException, IOException {
    WalletAddress walletAddress = this.generateWalletAddressByCustomPath(
        mnemonic, path);
    if (MnemonicUtils.generatedAddress(walletAddress.getAddress())) {
      terminal.writer().println("The path is already generated...");
      terminal.flush();
      return;
    }

    AttributedStringBuilder result = new AttributedStringBuilder()
        .append("Generate Address: ", AttributedStyle.BOLD)
        .append(walletAddress.address)
        .append("\n");
    terminal.writer().println(result.toAnsi());
    terminal.flush();
    String response = reader.readLine("Continue? (y/n): ").trim().toLowerCase();
    if (!response.equalsIgnoreCase("y")
        && !response.equalsIgnoreCase("yes")) {
      terminal.writer().println("Exiting...");
      return;
    }
    WalletFile walletFile = WalletApi.CreateWalletFile(password
        , walletAddress.privateKey
        , MnemonicUtils.stringToMnemonicWords(mnemonic)
    );
    String keystoreName = WalletApi.store2Keystore(walletFile);
    System.out.println("Generate a sub account successful, keystore file name is " + keystoreName);
  }

  private String handlePathInput() {
    try {
      printInstructions();
      String firstNumber = getValidInput("Enter first number: ", 0);
      String secondNumber = getValidInput("Enter second number: ", 1);
      String fullPath = buildFullPath(firstNumber, secondNumber);
      displayResult(fullPath, firstNumber, secondNumber);
      return fullPath;
    } catch (UserInterruptException e) {
      terminal.writer().println("\nOperation cancelled.");
    } catch (Exception e) {
      terminal.writer().println("\nAn error occurred: " + e.getMessage());
    }
    return "";
  }

  private void printInstructions() {
    AttributedStringBuilder asb = new AttributedStringBuilder()
        .append("Use Custom Path to Generate\n\n", AttributedStyle.BOLD)
        .append("Path format: ")
        .append(PATH_PREFIX + "X" + PATH_MIDDLE + "Y", AttributedStyle.BOLD)
        .append("\nwhere X and Y are numbers you will enter\n");

    terminal.writer().println(asb.toAnsi());
    terminal.flush();
  }

  private String getValidInput(String prompt, int position) {
    while (true) {
      try {
        AttributedStringBuilder asb = new AttributedStringBuilder()
            .append(prompt, AttributedStyle.BOLD);
        String input = reader.readLine(asb.toAnsi());
        if (!input.matches("^\\d+$")) {
          printError("Please enter a valid number");
          continue;
        }
        return input;
      } catch (UserInterruptException e) {
        throw e;
      } catch (Exception e) {
        printError("Invalid input: " + e.getMessage());
      }
    }
  }

  private void printError(String message) {
    terminal.writer().println(new AttributedStringBuilder()
        .append("Error: ", AttributedStyle.BOLD.foreground(AttributedStyle.RED))
        .append(message)
        .toAnsi());
    terminal.flush();
  }

  private String buildFullPath(String first, String second) {
    return PATH_PREFIX + first + PATH_MIDDLE + second;
  }

  private void displayResult(String path, String first, String second) throws Exception {
    clearScreen();
    AttributedStringBuilder result = new AttributedStringBuilder()
        .append("\nGenerate Path: ", AttributedStyle.BOLD)
        .append(path);
    terminal.writer().println(result.toAnsi());
    terminal.flush();
  }

}