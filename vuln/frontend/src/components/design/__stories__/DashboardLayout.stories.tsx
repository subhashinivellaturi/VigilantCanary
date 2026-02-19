import React from 'react';
import { Meta, Story } from '@storybook/react';
import { DashboardLayout } from '../DashboardLayout';

export default {
  title: 'Design/DashboardLayout',
  component: DashboardLayout,
} as Meta;

const Template: Story<any> = (args: any) => (
  <DashboardLayout>
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="p-6 bg-slate-800 rounded-xl">Content A</div>
        <div className="p-6 bg-slate-800 rounded-xl">Content B</div>
      </div>
    </div>
  </DashboardLayout>
);

export const Default = Template.bind({});
Default.args = {};
