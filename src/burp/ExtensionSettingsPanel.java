package burp;

import burp.api.montoya.MontoyaApi;

import java.util.Collection;
import java.util.Set;

class ExtensionSettingsPanel {

    private static volatile Object settingsPanel = null;

    static boolean isPanelAvailable() {
        return settingsPanel != null;
    }

    static final String VERIFY_GEMINI_KEY = "Verify Gemini API access (sends requests to Google)";

    static void register(MontoyaApi api) {
        try {
            ClassLoader cl = api.getClass().getClassLoader();
            Class<?> builderClass = Class.forName("burp.api.montoya.ui.settings.SettingsPanelBuilder", true, cl);
            Class<?> settingClass = Class.forName("burp.api.montoya.ui.settings.SettingsPanelSetting", true, cl);
            Class<?> persistenceClass = Class.forName("burp.api.montoya.ui.settings.SettingsPanelPersistence", true, cl);

            Object setting = settingClass
                    .getMethod("booleanSetting", String.class, boolean.class)
                    .invoke(null, VERIFY_GEMINI_KEY, false);

            @SuppressWarnings("unchecked")
            Object persistence = Enum.valueOf((Class<Enum>) persistenceClass, "USER_SETTINGS");

            Object panel = new ReflectiveBuilder(builderClass, builderClass.getMethod("settingsPanel").invoke(null))
                    .with("withTitle", String.class, "Google API Key Scan")
                    .with("withDescription", String.class,
                            "When enabled, detected API keys are checked against Google's Gemini API " +
                            "endpoints to confirm access. This upgrades findings from Information to " +
                            "Medium/High severity.")
                    .with("withSetting", settingClass, setting)
                    .with("withPersistence", persistenceClass, persistence)
                    .with("withKeywords", Collection.class, Set.of("activescan", "active", "scan", "google", "api", "key", "gemini"))
                    .build();

            api.userInterface().getClass()
                    .getMethod("registerSettingsPanel", Class.forName("burp.api.montoya.ui.settings.SettingsPanel", true, cl))
                    .invoke(api.userInterface(), panel);

            settingsPanel = panel;
        } catch (Exception e) {
            Utilities.err("Could not register settings panel (requires Burp 2025.6+): " + e.getMessage());
        }
    }

    static boolean getVerifyGeminiAccess() {
        if (settingsPanel == null) {
            return false;
        }
        try {
            return (Boolean) settingsPanel.getClass()
                    .getMethod("getBoolean", String.class)
                    .invoke(settingsPanel, VERIFY_GEMINI_KEY);
        } catch (Exception e) {
            Utilities.err("Failed to read Gemini verify setting: " + e.getMessage());
            return false;
        }
    }

    private static class ReflectiveBuilder {
        private final Class<?> cls;
        private Object obj;

        ReflectiveBuilder(Class<?> cls, Object obj) {
            this.cls = cls;
            this.obj = obj;
        }

        ReflectiveBuilder with(String method, Class<?> paramType, Object arg) throws Exception {
            obj = cls.getMethod(method, paramType).invoke(obj, arg);
            return this;
        }

        Object build() throws Exception {
            return cls.getMethod("build").invoke(obj);
        }
    }
}