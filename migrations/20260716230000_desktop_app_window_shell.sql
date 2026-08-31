-- App / window / GUI-session shell desktop commands.

INSERT INTO command_definitions (name, description, risk_level) VALUES
    ('desktop.app.launch', 'Launch an application in the GUI session', 'high'),
    ('desktop.window.list', 'List visible windows in the GUI session', 'low'),
    ('desktop.window.focus', 'Focus a window by id, title, or app', 'high'),
    ('desktop.window.wait', 'Wait until a matching window appears or is focused', 'low'),
    ('desktop.shell.run', 'Run an explicit argv process inside the GUI user session', 'high');
