import { useEffect, useState } from 'react';
import { getReactions, postReaction, type ReactionSummary } from '../api';

const choices = ['👍', '👀', '🙏', '😤', '🎉'];

export const Reactions = ({ incidentId }: { incidentId: number }) => {
  const [summary, setSummary] = useState<ReactionSummary | null>(null);

  useEffect(() => {
    getReactions(incidentId).then(setSummary).catch(() => setSummary(null));
  }, [incidentId]);

  const react = async (emoji: string) => {
    setSummary(await postReaction(incidentId, emoji));
  };

  return (
    <div className="reactions">
      <div className="reaction-tally">
        {summary?.reactions.map((reaction, index) => (
          <span key={index} className="reaction-chip">
            <span dangerouslySetInnerHTML={{ __html: reaction.emoji }} /> {reaction.count}
          </span>
        ))}
      </div>
      <div className="reaction-actions">
        {choices.map((emoji) => (
          <button key={emoji} type="button" onClick={() => react(emoji)}>
            {emoji}
          </button>
        ))}
      </div>
    </div>
  );
};
