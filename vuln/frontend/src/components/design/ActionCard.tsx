import React from 'react';
import { Card } from '../ui/Card';
import { Button } from '../ui/Button';

export interface ActionCardProps {
  title?: string;
  onPrimary?: () => void;
  onSecondary?: () => void;
}

/**
 * ActionCard for quick actions
 */
export const ActionCard: React.FC<ActionCardProps> = ({ title, onPrimary, onSecondary }) => {
  return (
    <Card title={title} className="p-4">
      <div className="flex gap-3">
        <Button onClick={onPrimary}>Run</Button>
        <Button variant="ghost" onClick={onSecondary}>More</Button>
      </div>
    </Card>
  );
};
