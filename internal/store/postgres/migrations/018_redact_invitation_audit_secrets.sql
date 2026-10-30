-- Legacy invite codes were exposed through the unscoped authenticated audit feed.
-- Revoke only invitations whose exact codes were logged; issue new invitations
-- after upgrading. New code records a non-secret message instead of the code.
DELETE FROM invites
WHERE code IN (
    SELECT details FROM audit_events WHERE type = 'network.invite_generated'
);

-- Preserve the event itself and its timestamps, actor and network scope.
UPDATE audit_events
SET details = 'invitation created'
WHERE type = 'network.invite_generated'
  AND details <> 'invitation created';
