INSERT INTO command_definitions (name, description, risk_level)
VALUES (
    'helper.install',
    'Install a missing signed helper package when the agent is already enrolled',
    'high'
)
ON CONFLICT (name) DO NOTHING;
