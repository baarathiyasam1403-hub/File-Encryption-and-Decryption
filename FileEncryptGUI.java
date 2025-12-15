import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.nio.file.*;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.SecureRandom;
import static java.nio.file.StandardOpenOption.CREATE_NEW;

// ===============================
// CO5: Interface (Abstraction)
// ===============================
interface CryptoEngine {
    byte[] encrypt(byte[] plain, char[] password) throws Exception;   // CO5
    byte[] decrypt(byte[] blob, char[] password) throws Exception;    // CO5
}

// ===============================================
// CO5: Implementation class (Inheritance + Polymorphism)
// ===============================================
class AesGcmCryptoEngine implements CryptoEngine {

    // CO1: Basic constants
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int KEY_BITS = 128;
    private static final int PBKDF2_ITER = 100_000;
    private static final int GCM_TAG_BITS = 128;

    @Override
    public byte[] encrypt(byte[] plain, char[] password) throws Exception {

        // CO2: Arrays + algorithmic operations
        byte[] salt = new byte[SALT_LEN];
        byte[] iv = new byte[IV_LEN];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(salt);
        rnd.nextBytes(iv);

        SecretKeySpec key = deriveAesKey(password, salt); // CO6

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // CO6
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] ct = cipher.doFinal(plain); // CO6

        // CO2: Array merging
        byte[] out = new byte[salt.length + iv.length + ct.length];
        System.arraycopy(salt, 0, out, 0, salt.length);
        System.arraycopy(iv, 0, out, salt.length, iv.length);
        System.arraycopy(ct, 0, out, salt.length + iv.length, ct.length);

        return out;
    }

    @Override
    public byte[] decrypt(byte[] blob, char[] password) throws Exception {

        // CO1 + CO2: Conditionals + array slicing
        if (blob.length < SALT_LEN + IV_LEN + 1)
            throw new IllegalArgumentException("Invalid encrypted file.");

        byte[] salt = new byte[SALT_LEN];
        byte[] iv = new byte[IV_LEN];
        byte[] ct = new byte[blob.length - SALT_LEN - IV_LEN];

        System.arraycopy(blob, 0, salt, 0, SALT_LEN);
        System.arraycopy(blob, SALT_LEN, iv, 0, IV_LEN);
        System.arraycopy(blob, SALT_LEN + IV_LEN, ct, 0, ct.length);

        SecretKeySpec key = deriveAesKey(password, salt); // CO6

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // CO6
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(ct); // CO6
    }

    private SecretKeySpec deriveAesKey(char[] password, byte[] salt) throws Exception {

        // CO3: String/char[] handling
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITER, KEY_BITS);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        SecretKeySpec sk = new SecretKeySpec(keyBytes, "AES");

        // CO2: Loop + array clearing
        for (int i = 0; i < keyBytes.length; i++) keyBytes[i] = 0;

        return sk;
    }
}

// ===============================================
// MAIN GUI CLASS (CO1–CO6)
// ===============================================
public class FileEncryptGUI extends JFrame {

    // CO4: OOP fields
    private final JTextField filePathField = new JTextField(28);
    private final JTextField idField = new JTextField(12);
    private final JPasswordField passwordField = new JPasswordField(16);
    private final JTextArea logArea = new JTextArea(12, 46);

    // CO6: Collections Framework
    private final Map<String, Path> repo = new HashMap<>();

    // CO5: Polymorphism (interface reference)
    private final CryptoEngine crypto = new AesGcmCryptoEngine();

    public FileEncryptGUI() {
        super("AES-GCM Encrypt/Decrypt"); // CO4
        logArea.setEditable(false);

        JButton browseBtn = new JButton("Browse");
        JButton encBtn = new JButton("Encrypt");
        JButton decBtn = new JButton("Decrypt by ID");
        JButton listBtn = new JButton("List Records");
        JButton decFromFileBtn = new JButton("Decrypt from file");

        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();

        // CO1: Layout logic
        g.insets = new Insets(6, 6, 6, 6);
        g.fill = GridBagConstraints.HORIZONTAL;

        // CO4: GUI building
        g.gridx=0; g.gridy=0; p.add(new JLabel("File:"), g);
        g.gridx=1; p.add(filePathField, g);
        g.gridx=2; p.add(browseBtn, g);

        g.gridx=0; g.gridy=1; p.add(new JLabel("Record ID:"), g);
        g.gridx=1; p.add(idField, g);

        g.gridx=0; g.gridy=2; p.add(new JLabel("Password:"), g);
        g.gridx=1; p.add(passwordField, g);

        g.gridx=0; g.gridy=3; p.add(encBtn, g);
        g.gridx=1; p.add(decBtn, g);
        g.gridx=2; p.add(listBtn, g);

        g.gridx=0; g.gridy=4; g.gridwidth=3; p.add(decFromFileBtn, g);

        g.gridx=0; g.gridy=5; g.gridwidth=3; p.add(new JScrollPane(logArea), g);

        add(p);
        pack();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        // CO4: Event-driven programming
        browseBtn.addActionListener(this::browseFile);
        encBtn.addActionListener(this::encryptFile);
        decBtn.addActionListener(this::decryptById);
        listBtn.addActionListener(this::listRecords);
        decFromFileBtn.addActionListener(this::decryptFromFile);
    }

    private void browseFile(ActionEvent e) {
        JFileChooser ch = new JFileChooser(); // CO4
        if (ch.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            filePathField.setText(ch.getSelectedFile().getAbsolutePath()); // CO3
        }
    }

    private void encryptFile(ActionEvent e) {
        try {
            // CO1: Input validation
            String id = idField.getText().trim();
            char[] pwd = passwordField.getPassword();
            Path in = Paths.get(filePathField.getText().trim());

            if (id.isEmpty()) { log("Error: Record ID cannot be empty."); return; }
            if (pwd.length == 0) { log("Error: Password cannot be empty."); return; }
            if (!Files.exists(in)) { log("Error: File not found."); return; }

            byte[] plain = Files.readAllBytes(in); // CO6

            byte[] encBlob = crypto.encrypt(plain, pwd); // CO5

            Path out = Paths.get(in.toString() + ".enc");
            Files.write(out, encBlob, CREATE_NEW); // CO6

            repo.put(id, out); // CO6
            log("Encrypted: " + out);

            clearPassword(pwd); // CO2
            passwordField.setText("");
        } catch (Exception ex) {
            log("Encryption error: " + ex.getMessage()); // CO6
        }
    }

    private void decryptById(ActionEvent e) {
        try {
            String id = idField.getText().trim();
            char[] pwd = passwordField.getPassword();

            if (id.isEmpty()) { log("Error: Record ID cannot be empty."); return; }
            if (pwd.length == 0) { log("Error: Password cannot be empty."); return; }

            Path encPath = repo.get(id); // CO6
            if (encPath == null) { log("Error: No record for id: " + id); return; }

            byte[] blob = Files.readAllBytes(encPath); // CO6
            byte[] dec = crypto.decrypt(blob, pwd); // CO5

            Path out = Paths.get("decrypted_" + id + ".bin");
            Files.write(out, dec, CREATE_NEW); // CO6
            log("Decrypted successfully: " + out);

            clearPassword(pwd);
            passwordField.setText("");
        } catch (AEADBadTagException badTag) {
            log("Error: Wrong password or corrupted file."); // CO6
        } catch (Exception ex) {
            log("Decryption error: " + ex.getMessage());
        }
    }

    private void decryptFromFile(ActionEvent e) {
        char[] pwd = passwordField.getPassword();
        if (pwd.length == 0) {
            log("Error: Password cannot be empty.");
            return;
        }

        JFileChooser ch = new JFileChooser();
        if (ch.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        Path encPath = ch.getSelectedFile().toPath();

        try {
            byte[] blob = Files.readAllBytes(encPath); // CO6
            byte[] dec = crypto.decrypt(blob, pwd); // CO5

            String baseName = encPath.getFileName().toString().replaceAll("\\.enc$", ""); // CO3
            Path out = encPath.resolveSibling("decrypted_" + baseName + ".bin");

            Files.write(out, dec, CREATE_NEW); // CO6
            log("Decrypted successfully: " + out);
        } catch (AEADBadTagException badTag) {
            log("Error: Wrong password or corrupted file.");
        } catch (Exception ex) {
            log("Decryption error: " + ex.getMessage());
        } finally {
            clearPassword(pwd);
            passwordField.setText("");
        }
    }

    private void listRecords(ActionEvent e) {
        if (repo.isEmpty()) { log("No records."); return; }
        for (var entry : repo.entrySet()) {
            log(entry.getKey() + " -> " + entry.getValue()); // CO6
        }
    }

    private void clearPassword(char[] pwd) {
        // CO2: Loop + array clearing
        for (int i = 0; i < pwd.length; i++) pwd[i] = 0;
    }

    private void log(String msg) {
        logArea.append(msg + "\n"); // CO3
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new FileEncryptGUI().setVisible(true)); // CO4
    }
}