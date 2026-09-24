import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { searchIncidents, type IncidentSearchHit } from '../api';

export const Search = () => {
  const [params, setParams] = useSearchParams();
  const query = params.get('q') ?? '';
  const [hits, setHits] = useState<IncidentSearchHit[]>([]);
  const [term, setTerm] = useState(query);

  useEffect(() => {
    if (query) {
      searchIncidents(query).then(setHits).catch(() => setHits([]));
    }
  }, [query]);

  return (
    <div className="search-page">
      <form
        onSubmit={(event) => {
          event.preventDefault();
          setParams({ q: term });
        }}
      >
        <input
          type="search"
          value={term}
          onChange={(event) => setTerm(event.target.value)}
          placeholder="Search incidents…"
        />
        <button className="btn btn-primary" type="submit">
          Search
        </button>
      </form>
      {query && (
        <h2>
          Results for <span dangerouslySetInnerHTML={{ __html: query }} />
        </h2>
      )}
      <ul className="search-results">
        {hits.map((hit) => (
          <li key={hit.id}>
            <strong>{hit.title}</strong>
            <span className={`pill severity-${hit.severity}`}>{hit.severity}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};
