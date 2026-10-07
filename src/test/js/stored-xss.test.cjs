/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

test('stored comments are inserted as text, including the seeded script', () => {
    const source = fs.readFileSync(
        path.resolve(__dirname, '../../main/resources/lessons/xss/js/stored-xss.js'),
        'utf8'
    );
    const payload = '<script>webgoat.customjs.phoneHome()</script>';
    const document = {};
    const comments = [];
    const list = {
        empty: () => { comments.length = 0; },
        append: comment => {
            assert.equal(typeof comment, 'object', 'comment markup must not be reparsed');
            comments.push(comment);
        }
    };

    function jquery(selector) {
        if (selector === document) return {ready: callback => callback()};
        if (selector === '#postComment') return {on: () => {}};
        if (selector === '#list') return list;
        if (typeof selector === 'string' && selector.startsWith('<li class="comment">')) {
            const fields = {};
            return {
                fields,
                find: field => ({text: value => { fields[field] = value; }})
            };
        }
        throw new Error('Unexpected HTML parser input: ' + selector);
    }
    jquery.get = (_url, callback) => callback([{user: 'guest', dateTime: 'today', text: payload}]);

    vm.runInNewContext(source, {$: jquery, document});

    assert.equal(comments.length, 1);
    assert.equal(comments[0].fields['.user'], 'guest');
    assert.equal(comments[0].fields['.time'], 'today');
    assert.equal(comments[0].fields.p, payload);
});
