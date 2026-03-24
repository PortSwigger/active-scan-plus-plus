package burp;

import burp.api.montoya.MontoyaApi;

import java.util.Collection;
import java.util.Set;

class ExtensionSettingsPanel {

    static final String VERIFY_GEMINI_KEY = "Verify Gemini API access (sends requests to Google)";
    private static final int MIN_SETTINGS_API_YEAR = 2025;
    private static final int MIN_SETTINGS_API_MAJOR = 6;

    private static volatile Object settingsPanel = null;

    static boolean isPanelAvailable() {
        return settingsPanel != null;
    }

    static void register(MontoyaApi api) {
        if (supportsBuilderApi(api)) {
            registerBuilderPanel(api);
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

    private static boolean supportsBuilderApi(MontoyaApi api) {
        try {
            String[] parts = api.burpSuite().version().name().split("\\.");
            int year = Integer.parseInt(parts[0]);
            int major = Integer.parseInt(parts[1]);
            return year > MIN_SETTINGS_API_YEAR || (year == MIN_SETTINGS_API_YEAR && major >= MIN_SETTINGS_API_MAJOR);
        } catch (Exception e) {
            Utilities.err("Could not parse Burp version, assuming legacy: " + e.getMessage());
            return false;
        }
    }

    private static void registerBuilderPanel(MontoyaApi api) {
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

    private static class ReflectiveBuilder {
        private final Class<?> cls;
        private Object builderInstance;

        ReflectiveBuilder(Class<?> cls, Object builderInstance) {
            this.cls = cls;
            this.builderInstance = builderInstance;
        }

        ReflectiveBuilder with(String method, Class<?> paramType, Object arg) throws Exception {
            builderInstance = cls.getMethod(method, paramType).invoke(builderInstance, arg);
            return this;
        }

        Object build() throws Exception {
            return cls.getMethod("build").invoke(builderInstance);
        }
    }
}

