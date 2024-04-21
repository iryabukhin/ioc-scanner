from scanner.agent import create_app, db

from scanner.config import ConfigManager, YamlConfigLoader
config_manager = ConfigManager()
config_manager.add_loader(YamlConfigLoader('config.yaml'))
config = config_manager.load_config()


app = create_app(config)

if __name__ == '__main__':
    app.run(debug=True)
