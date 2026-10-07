/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

test('the URL fragment is displayed as text, never parsed as markup', () => {
    const source = fs.readFileSync(
        path.resolve(__dirname, '../../main/resources/webgoat/static/js/goatApp/view/LessonContentView.js'),
        'utf8'
    );
    let view;
    const backbone = {View: {extend: definition => definition}};
    vm.runInNewContext(source, {
        define: (_dependencies, factory) => {
            view = factory({}, {}, backbone, {}, function () {}, function () {});
        }
    });

    const payload = '<img src=x onerror=alert(1)>';
    let displayed;
    const content = {
        text: value => { displayed = value; },
        html: () => { throw new Error('Untrusted route input reached an HTML parser'); }
    };
    view.showTestParam.call({$el: {find: () => content}}, payload);

    assert.equal(displayed, 'test:' + payload);
});
