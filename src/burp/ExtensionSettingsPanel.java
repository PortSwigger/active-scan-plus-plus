package burp;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.lang.reflect.Method;

class ExtensionSettingsPanel {

    private static final String VERIFY_GEMINI_KEY = "google-api-key.verify-gemini-access";

    private final JPanel panel;

    ExtensionSettingsPanel(MontoyaApi api) {
        panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        addGoogleApiKeySection(api);
    }

    private void addGoogleApiKeySection(MontoyaApi api) {
        boolean savedValue = "true".equals(api.persistence().extensionData().getString(VERIFY_GEMINI_KEY));
        BurpExtender.verifyGeminiAccess.set(savedValue);

        JCheckBox verifyCheckbox = new JCheckBox("Verify Gemini API access (sends requests to Google)");
        verifyCheckbox.setIconTextGap(8);
        verifyCheckbox.setSelected(savedValue);
        verifyCheckbox.addActionListener(e -> {
            boolean selected = verifyCheckbox.isSelected();
            BurpExtender.verifyGeminiAccess.set(selected);
            api.persistence().extensionData().setString(VERIFY_GEMINI_KEY, String.valueOf(selected));
        });

        Font defaultFont = UIManager.getFont("Label.font");
        if (defaultFont == null) {
            defaultFont = new JLabel().getFont();
        }
        float defaultSize = defaultFont.getSize();

        JLabel heading = new JLabel("Google API Key Scan");
        heading.setFont(defaultFont.deriveFont(Font.BOLD, (int) (1.2f * defaultSize)));
        heading.setAlignmentX(Component.LEFT_ALIGNMENT);
        heading.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));

        JTextArea description = new JTextArea(
                "When enabled, detected API keys are checked against Google's Gemini API " +
                "endpoints to confirm access. This upgrades findings from Information to " +
                "Medium/High severity.");
        description.setEditable(false);
        description.setFocusable(false);
        description.setLineWrap(true);
        description.setWrapStyleWord(true);
        description.setOpaque(false);
        description.setFont(defaultFont);
        description.setAlignmentX(Component.LEFT_ALIGNMENT);
        description.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

        verifyCheckbox.setAlignmentX(Component.LEFT_ALIGNMENT);

        panel.add(heading);
        panel.add(description);
        panel.add(verifyCheckbox);
    }

    static void register(MontoyaApi api) {
        try {
            ExtensionSettingsPanel settingsPanel = new ExtensionSettingsPanel(api);
            Object proxy = java.lang.reflect.Proxy.newProxyInstance(
                    api.getClass().getClassLoader(),
                    new Class[]{Class.forName("burp.api.montoya.ui.settings.SettingsPanel")},
                    (p, method, args) -> {
                        if ("uiComponent".equals(method.getName())) {
                            return settingsPanel.panel;
                        }
                        if ("keywords".equals(method.getName())) {
                            return java.util.Set.of("activescan", "active", "scan", "google", "api", "key", "gemini");
                        }
                        return null;
                    }
            );
            Method registerMethod = api.userInterface().getClass().getMethod(
                    "registerSettingsPanel", Class.forName("burp.api.montoya.ui.settings.SettingsPanel"));
            registerMethod.invoke(api.userInterface(), proxy);
            BurpExtender.settingsPanelAvailable = true;
        } catch (Exception e) {
            Utilities.err("Could not register settings panel (requires Burp 2025.5+): " + e.getMessage());
        }
    }
}
