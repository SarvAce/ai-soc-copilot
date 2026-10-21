import { useMemo } from 'react';
import {
  Background, BaseEdge, Controls, EdgeLabelRenderer, Handle, Position, ReactFlow,
  getBezierPath, type Edge, type EdgeProps, type Node, type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useStore } from '../store';
import {
  META, NODES, deriveEdges, edgeId, nodeState, type EdgeInfo, type NodeState,
} from '../pipeline';
import type { NodeEvent, NodeName } from '../types';
import { SourceFor } from './steps';

const W = 250;
const POS: Record<string, { x: number; y: number }> = {
  planner: { x: 0, y: 90 }, investigator: { x: 390, y: 90 }, evidence_gate: { x: 780, y: 90 },
  analyst_review: { x: 0, y: 420 }, report_gate: { x: 390, y: 420 }, reporter: { x: 780, y: 420 },
  finalize: { x: 0, y: 700 }, __end__: { x: 390, y: 725 },
};

interface StepNodeData extends Record<string, unknown> {
  node: NodeName; state: NodeState; runs: number; last?: NodeEvent; onOpen: (n: NodeName) => void;
}

function StepNode({ data }: NodeProps<Node<StepNodeData>>) {
  const m = META[data.node];
  const stateWord = { idle: 'not run', done: 'done', current: 'running now', waiting: 'waiting for analyst' }[data.state];
  return (
    <button className={`fnode state-${data.state}`} style={{ width: W }} onClick={() => data.onOpen(data.node)}
            aria-label={`Step ${m.n} ${m.title}, ${stateWord}, ran ${data.runs} times. Open details`}>
      {(['t', 'b', 'l', 'r'] as const).map((id) => (
        <span key={id}>
          <Handle id={id} type="target" position={{ t: Position.Top, b: Position.Bottom, l: Position.Left, r: Position.Right }[id]} />
          <Handle id={id} type="source" position={{ t: Position.Top, b: Position.Bottom, l: Position.Left, r: Position.Right }[id]} />
        </span>
      ))}
      <div className="fnode-top">
        <span className="stepcard-n" aria-hidden="true">{m.n}</span>
        <span className="fnode-title">{m.title}</span>
        <span className={`runs ${data.runs ? 'runs-on' : ''}`}>×{data.runs}</span>
      </div>
      <div className="fnode-sub">{m.role}</div>
      <div className="fnode-src"><SourceFor node={data.node} step={data.last} /></div>
      <div className="fnode-state">
        <span aria-hidden="true">{{ idle: '○', done: '●', current: '◉', waiting: '⏸' }[data.state]}</span> {stateWord}
        {data.last && data.state !== 'idle' && <> · <b>{data.last.decision}</b></>}
      </div>
    </button>
  );
}

function EndNode() {
  return (
    <div className="fnode fnode-end">
      <Handle id="l" type="target" position={Position.Left} />
      END
    </div>
  );
}

interface FlowEdgeData extends Record<string, unknown> { info: EdgeInfo; onOpen: (e: EdgeInfo) => void }

const SIDES: Record<string, { s: Position; t: Position; sh: string; th: string }> = {
  'planner>investigator': { s: Position.Right, t: Position.Left, sh: 'r', th: 'l' },
  'investigator>evidence_gate': { s: Position.Right, t: Position.Left, sh: 'r', th: 'l' },
  'evidence_gate>planner': { s: Position.Top, t: Position.Top, sh: 't', th: 't' },
  'evidence_gate>reporter': { s: Position.Bottom, t: Position.Top, sh: 'b', th: 't' },
  'reporter>report_gate': { s: Position.Left, t: Position.Right, sh: 'l', th: 'r' },
  'report_gate>reporter': { s: Position.Bottom, t: Position.Bottom, sh: 'b', th: 'b' },
  'report_gate>analyst_review': { s: Position.Left, t: Position.Right, sh: 'l', th: 'r' },
  'analyst_review>finalize': { s: Position.Bottom, t: Position.Top, sh: 'b', th: 't' },
  'finalize>__end__': { s: Position.Right, t: Position.Left, sh: 'r', th: 'l' },
};

function FlowEdge(props: EdgeProps<Edge<FlowEdgeData>>) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data } = props;
  const info = data!.info;
  const [path, lx, ly] = getBezierPath({
    sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition,
    curvature: info.loop ? 0.9 : 0.25,
  });
  const cls = ['fedge', info.taken ? 'fedge-taken' : 'fedge-idle', info.loop ? 'fedge-loop' : '',
    info.active ? 'fedge-active' : ''].join(' ');
  const clickable = info.taken;
  return (
    <>
      <BaseEdge id={id} path={path} className={cls} interactionWidth={24} />
      {info.active && (
        <circle r="8" className="packet">
          <animateMotion dur="1s" repeatCount="indefinite" path={path} />
        </circle>
      )}
      <EdgeLabelRenderer>
        <button
          className={`elabel ${cls}`} disabled={!clickable}
          style={{ transform: `translate(-50%, -50%) translate(${lx}px, ${ly + (info.loop ? (sourcePosition === Position.Top ? -34 : 34) : 0)}px)` }}
          onClick={() => data!.onOpen(info)}
          aria-label={`Edge ${info.source} to ${info.target}: ${info.label}${clickable ? '. Open payload' : ''}`}
        >
          {info.loop && info.taken && <span aria-hidden="true">↺ </span>}
          {info.label}{info.count > 1 ? ` ×${info.count}` : ''}
        </button>
      </EdgeLabelRenderer>
    </>
  );
}

const nodeTypes = { step: StepNode, end: EndNode };
const edgeTypes = { flow: FlowEdge };

export function FlowGraph({ onNode, onEdge }: {
  onNode: (n: NodeName) => void; onEdge: (e: EdgeInfo) => void;
}) {
  const { steps, revealed, status, theme } = useStore();
  const shown = steps.slice(0, revealed);
  const settled = revealed >= steps.length && status !== 'running';
  const paused = status === 'paused';

  const nodes = useMemo<Node[]>(() => {
    const list: Node[] = NODES.map((n) => ({
      id: n, type: 'step', position: POS[n]!, draggable: false,
      data: {
        node: n, state: nodeState(n, shown, settled, paused),
        runs: shown.filter((s) => s.node === n).length,
        last: [...shown].reverse().find((s) => s.node === n), onOpen: onNode,
      } satisfies StepNodeData,
    }));
    list.push({ id: '__end__', type: 'end', position: POS.__end__!, draggable: false, data: {} });
    return list;
  }, [shown, settled, paused, onNode]);

  const edges = useMemo<Edge[]>(() => deriveEdges(steps, revealed, settled, paused).map((info) => {
    const side = SIDES[edgeId(info.source, info.target)]!;
    return {
      id: info.id, source: info.source, target: info.target, type: 'flow',
      sourceHandle: side.sh, targetHandle: side.th,
      data: { info, onOpen: onEdge } satisfies FlowEdgeData,
    };
  }), [steps, revealed, settled, paused, onEdge]);

  return (
    <div className="flowbox">
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes}
                 colorMode={theme} fitView fitViewOptions={{ padding: 0.12 }} minZoom={0.3}
                 nodesConnectable={false} proOptions={{ hideAttribution: true }}
                 onEdgeClick={(_, edge) => {
                   const info = (edge.data as FlowEdgeData | undefined)?.info;
                   if (info?.taken) onEdge(info);
                 }}>
        <Background gap={26} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
