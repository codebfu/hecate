INSERT INTO command_definitions (name, description, risk_level) VALUES
    ('file.copy', 'Copy a file on the machine', 'high'),
    ('file.move', 'Move a file on the machine', 'high'),
    ('file.rename', 'Rename a file in its parent directory', 'high'),
    ('file.delete', 'Delete a file on the machine', 'high'),
    ('folder.mkdir', 'Create a single directory on the machine', 'high'),
    ('folder.rmdir', 'Remove an empty directory on the machine', 'high'),
    ('folder.rename', 'Rename a directory in its parent directory', 'high'),
    ('folder.move', 'Move a directory on the machine', 'high'),
    ('folder.copy', 'Recursively copy a directory on the machine', 'high');
