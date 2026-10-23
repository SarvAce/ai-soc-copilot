import { useEffect, useMemo, useRef } from 'react';
import {
  Background, BaseEdge, EdgeLabelRenderer, Handle, Position, ReactFlow,
  getBezierPath, useReactFlow, type Edge, type EdgeProps, type Node, type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useStore } from '../store';
import {
  META, NODES, deriveEdges, edgeId, nodeState, type EdgeInfo, type NodeState,
} from '../pipeline';
import type { NodeEvent, NodeName } from '../types';
import { SourceFor } from './steps';

const W = 210;
const NODE_H = 108;
const POS: Record<string, { x: number; y: number }> = {
  detector:       { x: 30,  y: 35 },
  planner:        { x: 270, y: 35 },
  investigator:   { x: 510, y: 35 },
  evidence_gate:  { x: 750, y: 35 },
  reporter:       { x: 750, y: 235 },
  report_gate:    { x: 510, y: 235 },
  analyst_review: { x: 270, y: 235 },
  finalize:       { x: 30,  y: 235 },
  __end__:        { x: 30,  y: 375 },
};

const DEFAULT_VIEWPORT = { x: 12, y: 15, zoom: 0.64 };

interface StepNodeData extends Record<string, unknown> {
  node: NodeName;
  state: NodeState;
  runs: number;
  isSelected: boolean;
  currentPass: number;
  last?: NodeEvent;
  onOpen: (n: NodeName) => void;
}

function StepNode({ data }: NodeProps<Node<StepNodeData>>) {
  if (!data?.node) return null;
  const m = META[data.node] ?? { n: 0, title: String(data.node), role: '', source: 'rule' as const, sourceNote: '' };
  const stateLabels: Record<NodeState, { word: string; glyph: string; cls: string }> = {
    idle: { word: 'PENDING', glyph: '○', cls: 'state-idle' },
    done: { word: 'DONE', glyph: '●', cls: 'state-done' },
    current: { word: 'ACTIVE', glyph: '◉', cls: 'state-current' },
    waiting: { word: 'PAUSED (HITL)', glyph: '⏸', cls: 'state-waiting' },
    failed: { word: 'RETRY / RE-PLAN', glyph: '▲', cls: 'state-failed' },
  };
  const st = stateLabels[data.state] ?? stateLabels.idle;

  return (
    <div
      className={`fnode ${st.cls} ${data.isSelected ? 'fnode-selected' : ''}`}
      style={{ width: W }}
      onClick={() => data.onOpen(data.node)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') data.onOpen(data.node); }}
      aria-label={`Agent Step ${m.n}: ${m.title}, ${st.word}, ran ${data.runs} time(s). Click to inspect.`}
    >
      {(['t', 'b', 'l', 'r'] as const).map((id) => (
        <span key={id}>
          <Handle id={id} type="target" position={{ t: Position.Top, b: Position.Bottom, l: Position.Left, r: Position.Right }[id]} />
          <Handle id={id} type="source" position={{ t: Position.Top, b: Position.Bottom, l: Position.Left, r: Position.Right }[id]} />
        </span>
      ))}
      <div className="fnode-top">
        <span className="stepcard-n" aria-hidden="true">{m.n}</span>
        <span className="fnode-title">{m.title}</span>
        {data.runs > 0 && (
          <span className={`runs runs-on`} title={`Ran ${data.runs} pass(es)`}>
            {data.runs > 1 ? `Pass ${data.currentPass}/${data.runs}` : '×1'}
          </span>
        )}
      </div>

      <div className="fnode-sub">{m.role}</div>

      <div className="fnode-src">
        <SourceFor node={data.node} step={data.last} />
      </div>

      <div className="fnode-state">
        <span className="state-badge-pill" aria-hidden="true">{st.glyph} {st.word}</span>
        {data.last && data.state !== 'idle' && (
          <span className="fnode-decision-pill"><b>{data.last.decision}</b></span>
        )}
      </div>
    </div>
  );
}

function EndNode() {
  return (
    <div className="fnode fnode-end">
      <Handle id="t" type="target" position={Position.Top} />
      <span>🏁 END</span>
    </div>
  );
}

interface FlowEdgeData extends Record<string, unknown> {
  info: EdgeInfo;
  onOpen: (e: EdgeInfo) => void;
}

const SIDES: Record<string, { s: Position; t: Position; sh: string; th: string }> = {
  'detector>planner': { s: Position.Right, t: Position.Left, sh: 'r', th: 'l' },
  'planner>investigator': { s: Position.Right, t: Position.Left, sh: 'r', th: 'l' },
  'investigator>evidence_gate': { s: Position.Right, t: Position.Left, sh: 'r', th: 'l' },
  'evidence_gate>planner': { s: Position.Top, t: Position.Top, sh: 't', th: 't' },
  'evidence_gate>reporter': { s: Position.Bottom, t: Position.Top, sh: 'b', th: 't' },
  'reporter>report_gate': { s: Position.Left, t: Position.Right, sh: 'l', th: 'r' },
  'report_gate>reporter': { s: Position.Bottom, t: Position.Bottom, sh: 'b', th: 'b' },
  'report_gate>analyst_review': { s: Position.Left, t: Position.Right, sh: 'l', th: 'r' },
  'analyst_review>finalize': { s: Position.Left, t: Position.Right, sh: 'l', th: 'r' },
  'finalize>__end__': { s: Position.Bottom, t: Position.Top, sh: 'b', th: 't' },
};

function FlowEdge(props: EdgeProps<Edge<FlowEdgeData>>) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data } = props;
  if (!data?.info) return null;
  const info = data.info;
  const [path, lx, ly] = getBezierPath({
    sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition,
    curvature: info.loop ? 0.85 : 0.25,
  });
  if (isNaN(lx) || isNaN(ly)) return null;

  const cls = [
    'fedge',
    info.taken ? 'fedge-taken' : 'fedge-idle',
    info.loop ? 'fedge-loop' : '',
    info.active ? 'fedge-active' : '',
    info.highlighted ? 'fedge-highlighted' : '',
  ].filter(Boolean).join(' ');

  const clickable = info.taken;

  // Offset label position for top/bottom arched loop edges
  let labelY = ly;
  if (info.loop) {
    labelY = sourcePosition === Position.Top ? ly - 36 : ly + 36;
  }

  return (
    <>
      <BaseEdge id={id} path={path} className={cls} interactionWidth={28} />
      {info.active && (
        <circle r="7" className="packet">
          <animateMotion dur="0.9s" repeatCount="indefinite" path={path} />
        </circle>
      )}
      <EdgeLabelRenderer>
        <button
          className={`elabel ${cls}`}
          disabled={!clickable}
          style={{ transform: `translate(-50%, -50%) translate(${lx}px, ${labelY}px)` }}
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

function FitViewOnInit() {
  const { fitView } = useReactFlow();
  const initialDone = useRef(false);

  useEffect(() => {
    if (!initialDone.current) {
      initialDone.current = true;
      const timer = setTimeout(() => {
        fitView({ padding: 0.05, minZoom: 0.45, maxZoom: 0.70, duration: 0 });
      }, 50);
      return () => clearTimeout(timer);
    }
  }, [fitView]);

  return null;
}

function CanvasControls() {
  const { zoomIn, zoomOut, fitView, setViewport } = useReactFlow();
  return (
    <div className="flow-canvas-controls" role="toolbar" aria-label="Workflow canvas zoom and view controls">
      <button onClick={() => zoomIn({ duration: 200 })} title="Zoom In (+)" aria-label="Zoom in">
        <span aria-hidden="true">＋</span> Zoom In
      </button>
      <button onClick={() => zoomOut({ duration: 200 })} title="Zoom Out (−)" aria-label="Zoom out">
        <span aria-hidden="true">－</span> Zoom Out
      </button>
      <button onClick={() => fitView({ padding: 0.05, duration: 250, minZoom: 0.45, maxZoom: 0.70 })} title="Fit View to Screen" aria-label="Fit view to all nodes">
        <span aria-hidden="true">⛶</span> Fit View
      </button>
      <button onClick={() => {
        setViewport(DEFAULT_VIEWPORT, { duration: 250 });
      }} title="Reset View" aria-label="Reset view coordinates">
        <span aria-hidden="true">↺</span> Reset View
      </button>
    </div>
  );
}

export function FlowGraph({
  selectedNode, selectedPass, onNode, onEdge,
}: {
  selectedNode: NodeName | null;
  selectedPass: number;
  onNode: (n: NodeName) => void;
  onEdge: (e: EdgeInfo) => void;
}) {
  const { steps, revealed, status, theme, caseId, stage1 } = useStore();
  const shown = steps.slice(0, revealed);
  const settled = revealed >= steps.length && status !== 'running';
  const paused = status === 'paused';
  const hasCase = Boolean(caseId && stage1?.cases.length);

  const nodes = useMemo<Node[]>(() => {
    const list: Node[] = NODES.map((n) => {
      const execs = shown.filter((s) => s.node === n);
      const isSelected = selectedNode === n;
      return {
        id: n,
        type: 'step',
        position: POS[n]!,
        draggable: false,
        initialWidth: W,
        initialHeight: NODE_H,
        width: W,
        measured: { width: W, height: NODE_H },
        data: {
          node: n,
          state: nodeState(n, shown, settled, paused, hasCase),
          runs: execs.length,
          isSelected,
          currentPass: isSelected ? selectedPass : execs.length,
          last: [...shown].reverse().find((s) => s.node === n),
          onOpen: onNode,
        } satisfies StepNodeData,
      };
    });
    list.push({
      id: '__end__',
      type: 'end',
      position: POS.__end__!,
      draggable: false,
      initialWidth: 140,
      initialHeight: 45,
      width: 140,
      measured: { width: 140, height: 45 },
      data: {},
    });
    return list;
  }, [shown, settled, paused, hasCase, selectedNode, selectedPass, onNode]);

  const caseObj = stage1?.cases.find((c) => c.case_id === caseId) ?? null;

  const edges = useMemo<Edge[]>(() => {
    return deriveEdges(steps, revealed, settled, paused, selectedNode, caseObj).map((info) => {
      const side = SIDES[edgeId(info.source, info.target)] ?? { sh: 'r', th: 'l', s: Position.Right, t: Position.Left };
      return {
        id: info.id,
        source: info.source,
        target: info.target,
        type: 'flow',
        sourceHandle: side.sh,
        targetHandle: side.th,
        data: { info, onOpen: onEdge } satisfies FlowEdgeData,
      };
    });
  }, [steps, revealed, settled, paused, selectedNode, caseObj, onEdge]);

  return (
    <div className="flowbox">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        colorMode={theme}
        defaultViewport={DEFAULT_VIEWPORT}
        minZoom={0.25}
        maxZoom={1.5}
        nodesConnectable={false}
        nodesDraggable={false}
        panOnDrag={true}
        zoomOnScroll={false}
        preventScrolling={false}
        proOptions={{ hideAttribution: true }}
        onEdgeClick={(_, edge) => {
          const info = (edge.data as FlowEdgeData | undefined)?.info;
          if (info?.taken) onEdge(info);
        }}
      >
        <Background gap={24} size={1} />
        <FitViewOnInit />
        <CanvasControls />
      </ReactFlow>
    </div>
  );
}
