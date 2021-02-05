-- add the user table record
INSERT INTO j_users
(name, username, email, password, block, sendEmail, registerDate, lastvisitDate, activation, params, lastResetTime, resetCount, otpKey, otep, requireReset)
VALUES('Super User Test', 'test', 'test@test.test', MD5('test'), 0, 1, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', '', '0000-00-00 00:00:00', 0, '', '', 0);
-- add to the usergroup so we're superadmins
INSERT INTO j_user_usergroup_map
(user_id,group_id)
VALUES (1,8);