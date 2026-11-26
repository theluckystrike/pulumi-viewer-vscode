'use strict';
module.exports = {
  prefix: 'zovoPulumi',
  triesKey: 'zovoPulumi.proTrial',
  slot: '#protools',
  tools: [
    { id: 'auditStack', title: 'Audit Pulumi stack secret hygiene', command: 'zovoPulumi.auditStack' },
    { id: 'diffStacks', title: 'Compare two Pulumi stack files', command: 'zovoPulumi.diffStacks' },
    { id: 'exportConfigDoc', title: 'Export redacted config inventory', command: 'zovoPulumi.exportConfigDoc' },
  ],
};
